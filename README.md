# axelar-service-registry
# Message Semantics
Structure of a routing packet (`M` in the diagrams)
```rust
    struct Message {
        id: String,
        source_address: String,
        source_chain: String
        destination_address: String,
        destination_chain: String,
        payload_hash: HexBinary
    }
```
# High Level Architecture
```mermaid
flowchart TD
subgraph Axelar
	G{"Gateway"}
	Vr{"Verifier"}
	Vo{"Voting verifier"}
	Lc{"Light Client verifier"}
	R{"Router"}
end

Relayer --"ValidateMessage(M)"-->G
G --"VerifyMessage(M)"--> Vr
Vr --"VerifyMessage(M)"--> Vo
Vr --"VerifyMessage(M)"--> Lc

Relayer --"ExecuteMessage(M)"-->G
G --"RouteMessage(M)"-->R
```
As an optimization `VerifyMessage(M)` can be replaced with `VerifyMessage(M.id, hash(M))`

# Event Flow

### Universal Gateway Interface
Any cross chain message execution requires these four steps:
1. Relay the message
2. Check for validation
3. Check for prior execution and mark as executed (to prevent replay attacks)
4. Execute the app specific logic

Gateways need to decide if they will support and expose step 4 or step 3 (like EVM gateways).
Gateways expose the highest step they support, which internally calls prior steps.
For example, if a gateway exposes 4, the method would first check for validation, check for prior execution
and mark the message as executed before actually executing the payload. If any of the checks fails, the whole
method fails.

Optionally, gateways can choose to expose any intermediate steps as well to support specific execution flows.
For example, if a gateway is using a validation method(s) that needs to be triggered, such as RPC voting,
that gateway could expose 1 or 2 as a way for relayers to trigger validation. 

When executing app specific logic, if the gateway is not actually the final destination of the chain, the
execute method (4) just accepts the routing packet, instead of the actual payload.

## Voting Contract Flows
ValidateMessage -> Poll -> ExecuteMessage
```mermaid
sequenceDiagram
    participant Relayer
    participant Gateway
    participant Verifier
    participant Voting Verifier
    participant OffChain Voting Worker
    participant Router
    Relayer->>Gateway: ValidateMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier->>Voting Verifier: VerifyMessage(M)
    Voting Verifier->>OffChain Voting Worker: emit event
    Voting Verifier-->>Verifier: false
    Verifier-->>Gateway: false
    Gateway->>Gateway: Store message, mark as not validated
    Gateway-->>Relayer: false
    OffChain Voting Worker->>Voting Verifier: StartPoll
    OffChain Voting Worker->>Voting Verifier: Vote
    OffChain Voting Worker->>Voting Verifier: Vote
    OffChain Voting Worker->>Voting Verifier: EndPoll
    Voting Verifier->>Verifier: MessageVerified(M)
    Verifier->>Gateway: MessageVerified(M)
    Gateway->>Gateway: mark message as validated
    Gateway->>Relayer: emit message verified event



    Relayer->>Gateway: ExecuteMessage(M)
    Gateway->>Gateway: ValidateMessage(M)
    Gateway->>Gateway: message already stored as validated
    Gateway->>Gateway: mark message as executed
    Gateway->>Router: RouteMessage(M)
```

Poll -> ValidateMessage -> ExecuteMessage
```mermaid
sequenceDiagram
    participant Relayer
    participant Gateway
    participant Verifier
    participant Voting Verifier
    participant OffChain Voting Worker
    participant Router
    OffChain Voting Worker->>Voting Verifier: StartPoll
    OffChain Voting Worker->>Voting Verifier: Vote
    OffChain Voting Worker->>Voting Verifier: Vote
    OffChain Voting Worker->>Voting Verifier: EndPoll

    Voting Verifier->>Verifier: MessageVerified(M)
    Verifier->>Gateway: MessageVerified(M)
    Gateway->>Gateway: store message, mark as validated

    Relayer->>Gateway: ValidateMessage(M)
    Gateway->>Gateway: message already stored as validated
    Gateway-->>Relayer: true

    Relayer->>Gateway: ExecuteMessage(M)
    Gateway->>Gateway: ValidateMessage(M)
    Gateway->>Gateway: message already stored as validated
    Gateway->>Gateway: mark message as executed
    Gateway->>Router: RouteMessage(M)
```
ExecuteMessage -> Poll -> ExecuteMessage
```mermaid
sequenceDiagram
    participant Relayer
    participant Gateway
    participant Verifier
    participant Voting Verifier
    participant OffChain Voting Worker
    participant Router
    Relayer->>Gateway: ExecuteMessage(M)
    Gateway->>Gateway: ValidateMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier->>Voting Verifier: VerifyMessage(M)
    Voting Verifier->>OffChain Voting Worker: emit event
    Voting Verifier-->>Verifier: false
    Verifier-->>Gateway: false
    Gateway->>Gateway: Store message, mark as not validated
    Gateway->>Relayer: false
    OffChain Voting Worker->>Voting Verifier: StartPoll
    OffChain Voting Worker->>Voting Verifier: Vote
    OffChain Voting Worker->>Voting Verifier: Vote
    OffChain Voting Worker->>Voting Verifier: EndPoll


    Voting Verifier->>Verifier: MessageVerified(M)
    Verifier->>Gateway: MessageVerified(M)
    Gateway->>Gateway: mark message as validated
    Gateway->>Relayer: emit message verified event



    Relayer->>Gateway: ExecuteMessage(M)
    Gateway->>Gateway: ValidateMessage(M)
    Gateway->>Gateway: message already stored as validated
    Gateway->>Gateway: mark message as executed
    Gateway->>Router: RouteMessage(M)
```

Poll -> ExecuteMessage
```mermaid
sequenceDiagram
    participant Relayer
    participant Gateway
    participant Verifier
    participant Voting Verifier
    participant OffChain Voting Worker
    participant Router

    OffChain Voting Worker->>Voting Verifier: StartPoll
    OffChain Voting Worker->>Voting Verifier: Vote
    OffChain Voting Worker->>Voting Verifier: Vote
    OffChain Voting Worker->>Voting Verifier: EndPoll

    Voting Verifier->>Verifier: MessageVerified(M)
    Verifier->>Gateway: MessageVerified(M)
    Gateway->>Gateway: store message, mark as validated
    Gateway->>Relayer: emit message verified event

    Relayer->>Gateway: ExecuteMessage(M)
    Gateway->>Gateway: ValidateMessage(M)
    Gateway->>Gateway: message already stored as validated
    Gateway->>Gateway: mark message as executed
    Gateway->>Router: RouteMessage(M)
```

## Light client Flows


```mermaid
sequenceDiagram
    participant Relayer
    participant Gateway
    participant Verifier
    participant Light Client Verifier
    participant Light Client Relayer
    participant Router

    Light Client Relayer->>Light Client Verifier: Relay block header

    Relayer->>Gateway: ValidateMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier->>Light Client Verifier: VerifyMessage(M)
    Light Client Verifier->>Light Client Relayer: emit event
    Light Client Verifier-->>Verifier: false
    Verifier-->>Gateway: false
    Gateway->>Gateway: Store message, mark as not validated

    Light Client Relayer->>Light Client Verifier: Relay merkle tree inclusion proof for M
    Light Client Verifier->>Verifier: MessageVerified(M)
    Verifier->>Gateway: MessageVerified(M)
    Gateway->>Gateway: store message, mark as validated
    Gateway->>Relayer: emit message verified even    Verifier->>Light Client Verifier: VerifyMessage(M)
    Light Client Verifier-->>Verifier: truet


    Relayer->>Gateway: ExecuteMessage(M)
    Gateway->>Gateway: ValidateMessage(M)
    Gateway->>Gateway: message already stored as validated
    Gateway->>Gateway: mark message as executed
    Gateway->>Router: RouteMessage(M)
```

```mermaid
sequenceDiagram
    participant Relayer
    participant Gateway
    participant Verifier
    participant Light Client Verifier
    participant Light Client Relayer
    participant Router

    Light Client Relayer->>Light Client Verifier: Relay block header

    Relayer->>Gateway: ExecuteMessage(M)
    Gateway->>Gateway: ValidateMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier->>Light Client Verifier: VerifyMessage(M)
    Light Client Verifier->>Light Client Relayer: emit event
    Light Client Verifier-->>Verifier: false
    Verifier-->>Gateway: false
    Gateway-->>Relayer: false

    Light Client Relayer->>Light Client Verifier: Relay merkle tree inclusion proof for M

    Light Client Verifier->>Verifier: MessageVerified(M)
    Verifier->>Gateway: MessageVerified(M)
    Gateway->>Gateway: store message, mark as validated
    Gateway->>Relayer: emit message verified event

    Relayer->>Gateway: ExecuteMessage(M)
    Gateway->>Gateway: ValidateMessage(M)
    Gateway->>Gateway: message already stored as validated
    Gateway->>Gateway: mark message as executed
    Gateway->>Router: RouteMessage(M)
```

```mermaid
sequenceDiagram
    participant Relayer
    participant Gateway
    participant Verifier
    participant Light Client Verifier
    participant Light Client Relayer
    participant Router

    Light Client Relayer->>Light Client Verifier: Relay block header
    Light Client Relayer->>Light Client Verifier: Relay merkle tree inclusion proof for M
    Light Client Verifier->>Verifier: MessageVerified(M)
    Verifier->>Gateway: MessageVerified(M)
    Gateway->>Gateway: store message, mark as validated
    Gateway->>Relayer: emit message verified event

    Relayer->>Gateway: ValidateMessage(M)
    Gateway->>Gateway: message already stored as validated
    Gateway-->>Relayer: true

    Relayer->>Gateway: ExecuteMessage(M)
    Gateway->>Gateway: ValidateMessage(M)
    Gateway->>Gateway: message already stored as validated
    Gateway->>Gateway: mark message as executed
    Gateway->>Router: RouteMessage(M)
```


```mermaid
sequenceDiagram
    participant Relayer
    participant Gateway
    participant Verifier
    participant Light Client Verifier
    participant Light Client Relayer
    participant Router

    Light Client Relayer->>Light Client Verifier: Relay block header
    Light Client Relayer->>Light Client Verifier: Relay merkle tree inclusion proof for M
    Light Client Verifier->>Verifier: MessageVerified(M)
    Verifier->>Gateway: MessageVerified(M)
    Gateway->>Gateway: store message, mark as validated
    Gateway->>Relayer: emit message verified event


    Relayer->>Gateway: ExecuteMessage(M)
    Gateway->>Gateway: ValidateMessage(M)
    Gateway->>Gateway: message already stored as validated
    Gateway->>Gateway: mark message as executed
    Gateway->>Router: RouteMessage(M)
```


```mermaid
sequenceDiagram
    participant Relayer
    participant Gateway
    participant Verifier
    participant Light Client Verifier
    participant Light Client Relayer
    participant Router


    Relayer->>Gateway: ValidateMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier->>Light Client Verifier: VerifyMessage(M)
    Light Client Verifier->>Light Client Relayer: emit event
    Light Client Verifier-->>Verifier: false
    Verifier-->>Gateway: false
    Gateway->>Gateway: Store message, mark as not validated

    Light Client Relayer->>Light Client Verifier: Relay block header
    Light Client Relayer->>Light Client Verifier: Relay merkle tree inclusion proof for M

    Light Client Verifier->>Verifier: MessageVerified(M)
    Verifier->>Gateway: MessageVerified(M)
    Gateway->>Gateway: store message, mark as validated
    Gateway->>Relayer: emit message verified event

    Relayer->>Gateway: ValidateMessage(M)
    Gateway->>Gateway: message already stored as validated
    Gateway-->>Relayer: true

    Relayer->>Gateway: ExecuteMessage(M)
    Gateway->>Gateway: ValidateMessage(M)
    Gateway->>Gateway: message already stored as validated
    Gateway->>Gateway: mark message as executed
    Gateway->>Router: RouteMessage(M)
```
```mermaid
sequenceDiagram
    participant Relayer
    participant Gateway
    participant Verifier
    participant Light Client Verifier
    participant Light Client Relayer
    participant Router


    Relayer->>Gateway: ExecuteMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier->>Light Client Verifier: VerifyMessage(M)
    Light Client Verifier->>Light Client Relayer: emit event
    Light Client Verifier-->>Verifier: false
    Verifier-->>Gateway: false
    Gateway->>Gateway: store message, mark as not validated

    Light Client Relayer->>Light Client Verifier: Relay block header
    Light Client Relayer->>Light Client Verifier: Relay merkle tree inclusion proof for M

    Light Client Verifier->>Verifier: MessageVerified(M)
    Verifier->>Gateway: MessageVerified(M)
    Gateway->>Gateway: mark as validated
    Gateway->>Relayer: emit message verified event

    Relayer->>Gateway: ExecuteMessage(M)
    Gateway->>Gateway: ValidateMessage(M)
    Gateway->>Gateway: message already stored as validated
    Gateway->>Gateway: mark message as executed
    Gateway->>Router: RouteMessage(M)
```

## Multiple validation methods
Assume the security policy is both light client and rpc voting validations are needed for a message to be considered fully validated.


```mermaid
sequenceDiagram
    participant Relayer
    participant Gateway
    participant Verifier
    participant Light Client Verifier
    participant Voting Verifier
    participant Light Client Relayer
    participant OffChain Voting Worker
    participant Router


    Light Client Relayer->>Light Client Verifier: Relay block header
    Light Client Relayer->>Light Client Verifier: Relay merkle tree inclusion proof for M
    Light Client Verifier->>Verifier: MessageVerified(M)
    Verifier->>Verifier: store message as verified by light client
    Relayer->>Gateway: ValidateMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier->>Verifier: light client already verified
    Verifier->>Voting Verifier: VerifyMessage(M)
    Voting Verifier->>OffChain Voting Worker: emit event
    Voting Verifier-->>Verifier: false
    Verifier-->>Gateway: false
    Gateway->>Gateway: Store message, mark as not validated
    Gateway-->>Relayer: false

    OffChain Voting Worker->>Voting Verifier: StartPoll
    OffChain Voting Worker->>Voting Verifier: Vote
    OffChain Voting Worker->>Voting Verifier: Vote
    OffChain Voting Worker->>Voting Verifier: EndPoll

    Voting Verifier->>Verifier: MessageVerified(M)
    Verifier->>Verifier: security policy is met
    Verifier->>Gateway: MessageVerified(M)
    Gateway->>Gateway: store message, mark as validated
    Gateway->>Relayer: emit message verified event

    Relayer->>Gateway: ExecuteMessage(M)
    Gateway->>Gateway: ValidateMessage(M)
    Gateway->>Gateway: message already stored as validated
    Gateway->>Gateway: mark message as executed
    Gateway->>Router: RouteMessage(M)
```


```mermaid
sequenceDiagram
    participant Relayer
    participant Gateway
    participant Verifier
    participant Light Client Verifier
    participant Voting Verifier
    participant Light Client Relayer
    participant OffChain Voting Worker
    participant Router


    Light Client Relayer->>Light Client Verifier: Relay block header
    Relayer->>Gateway: ValidateMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier->>Light Client Verifier: VerifyMessage(M)
    Light Client Verifier->>Light Client Relayer: emit event
    Light Client Verifier-->>Verifier: false
    Verifier->>Voting Verifier: VerifyMessage(M)
    Voting Verifier->>OffChain Voting Worker: emit event
    Voting Verifier-->>Verifier: false
    Verifier-->>Gateway: false
    Gateway->>Gateway: Store message, mark as not validated

    Light Client Relayer->>Light Client Verifier: Relay merkle tree inclusion proof for M
    Light Client Verifier->>Verifier: MessageVerified(M)
    Verifier->>Verifier: store message as verified by light client

    OffChain Voting Worker->>Voting Verifier: StartPoll
    OffChain Voting Worker->>Voting Verifier: Vote
    OffChain Voting Worker->>Voting Verifier: Vote
    OffChain Voting Worker->>Voting Verifier: EndPoll

    Voting Verifier->>Verifier: MessageVerified(M)
    Verifier->>Verifier: security policy is met
    Verifier->>Gateway: MessageVerified(M)
    Gateway->>Gateway: store message, mark as validated
    Gateway->>Relayer: emit message verified event


    Relayer->>Gateway: ValidateMessage(M)
    Gateway->>Gateway: message already stored as validated
    Gateway-->>Relayer: true

    Relayer->>Gateway: ExecuteMessage(M)
    Gateway->>Gateway: ValidateMessage(M)
    Gateway->>Gateway: message already stored as validated
    Gateway->>Gateway: mark message as executed
    Gateway->>Router: RouteMessage(M)
```
## EVM Gateway flows

```mermaid
sequenceDiagram
    participant Relayer
    participant Execution Service
    participant Destination Contract
    participant Gateway
    participant Verifier

    Relayer->>Verifier: Relay signed batch

    Relayer->>Gateway: ValidateMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier-->>Gateway: true
    Gateway->>Gateway: mark message as validated

    Execution Service->>Destination Contract: ExecuteMessage(M)
    Destination Contract->>Gateway: ExecuteMessage(M)
    Gateway->>Gateway: mark message as executed
    Gateway-->>Destination Contract: execution approved 
    Destination Contract->>Destination Contract: execute payload

```


```mermaid
sequenceDiagram
    participant Relayer
    participant Destination Contract
    participant Gateway
    participant Verifier

    Relayer->>Verifier: Relay signed batch

    Relayer->>Destination Contract: ExecuteMessage(M)
    Destination Contract->>Gateway: ExecuteMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier-->>Gateway: true
    Gateway->>Gateway: mark message as executed
    Gateway-->>Destination Contract: execution approved 
    Destination Contract->>Destination Contract: execute payload

```

```mermaid
sequenceDiagram
    participant Relayer
    participant Validation Service
    participant Execution Service
    participant Destination Contract
    participant Gateway
    participant Verifier

    Relayer->>Gateway: ValidateMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier-->>Gateway: false
    Gateway->>Gateway: store message, mark as not validated

    Validation Service->>Verifier: Relay signed batch

    Relayer->>Gateway: ValidateMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier-->>Gateway: true
    Gateway->>Gateway: mark message as validated

    Execution Service->>Destination Contract: ExecuteMessage(M)
    Destination Contract->>Gateway: ExecuteMessage(M)
    Gateway->>Gateway: mark message as executed
    Gateway-->>Destination Contract: execution approved 
    Destination Contract->>Destination Contract: execute payload

```


```mermaid
sequenceDiagram
    participant Validation Service
    participant Execution Service
    participant Destination Contract
    participant Gateway
    participant Verifier


    Validation Service->>Verifier: Relay signed batch


    Execution Service->>Destination Contract: ExecuteMessage(M)
    Destination Contract->>Gateway: ExecuteMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier-->>Gateway: true
    Gateway->>Gateway: mark message as executed
    Gateway-->>Destination Contract: execution approved
    Destination Contract->>Destination Contract: execute payload

```



```mermaid
sequenceDiagram
    participant Validation Service
    participant Execution Service
    participant Destination Contract
    participant Gateway
    participant Verifier




    Execution Service->>Destination Contract: ExecuteMessage(M)
    Destination Contract->>Gateway: ExecuteMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier-->>Gateway: false
    Gateway->>Gateway: store message, mark as not validated
    Gateway-->>Destination Contract: execution not approved
    Destination Contract->>Destination Contract: call fails

    Validation Service->>Verifier: Relay signed batch

    Execution Service->>Destination Contract: ExecuteMessage(M)
    Destination Contract->>Gateway: ExecuteMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier-->>Gateway: true
    Gateway->>Gateway: mark message as executed
    Gateway-->>Destination Contract: execution approved
    Destination Contract->>Destination Contract: execute payload

```



