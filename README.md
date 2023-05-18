# axelar-service-registry
# Message Semantics
Structure of a routing packet (`M` in the diagrams)
```rust
    struct Message {
        id: String,
        source_address: String,
        destination_address: String,
        destination_domain: String,
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

## Voting Contract Flows
ValidateMessage -> Poll -> ValidateMessage -> ExecuteMessage
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
    Voting Verifier-->>Verifier: false
    Verifier-->>Gateway: false
    Gateway->>Gateway: Store message, mark as not validated
    OffChain Voting Worker->>Voting Verifier: StartPoll
    OffChain Voting Worker->>Voting Verifier: Vote
    OffChain Voting Worker->>Voting Verifier: Vote
    OffChain Voting Worker->>Voting Verifier: EndPoll


    Relayer->>Gateway: ValidateMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier->>Voting Verifier: VerifyMessage(M)
    Voting Verifier-->>Verifier: true
    Verifier-->>Gateway: true
    Gateway->>Gateway: store message, mark as validated

    Relayer->>Gateway: ExecuteMessage(M)
    Gateway->>Router: RouteMessage(M)
```
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
    Voting Verifier-->>Verifier: false
    Verifier-->>Gateway: false
    Gateway->>Gateway: Store message, mark as not validated
    OffChain Voting Worker->>Voting Verifier: StartPoll
    OffChain Voting Worker->>Voting Verifier: Vote
    OffChain Voting Worker->>Voting Verifier: Vote
    OffChain Voting Worker->>Voting Verifier: EndPoll



    Relayer->>Gateway: ExecuteMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier->>Voting Verifier: VerifyMessage(M)
    Voting Verifier-->>Verifier: true
    Verifier-->>Gateway: true
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

    Relayer->>Gateway: ValidateMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier->>Voting Verifier: VerifyMessage(M)
    Voting Verifier-->>Verifier: true
    Verifier-->>Gateway: true
    Gateway->>Gateway: store message, mark as validated

    Relayer->>Gateway: ExecuteMessage(M)
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
    Gateway->>Verifier: VerifyMessage(M)
    Verifier->>Voting Verifier: VerifyMessage(M)
    Voting Verifier-->>Verifier: false
    Verifier-->>Gateway: false
    Gateway->>Gateway: Store message, mark as not validated
    OffChain Voting Worker->>Voting Verifier: StartPoll
    OffChain Voting Worker->>Voting Verifier: Vote
    OffChain Voting Worker->>Voting Verifier: Vote
    OffChain Voting Worker->>Voting Verifier: EndPoll


    Relayer->>Gateway: ExecuteMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier->>Voting Verifier: VerifyMessage(M)
    Voting Verifier-->>Verifier: true
    Verifier-->>Gateway: true
    Gateway->>Gateway: store message, mark as validated

    Relayer->>Gateway: ExecuteMessage(M)
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

    Relayer->>Gateway: ExecuteMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier->>Voting Verifier: VerifyMessage(M)
    Voting Verifier-->>Verifier: true
    Verifier-->>Gateway: true
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
    Light Client Verifier-->>Verifier: false
    Verifier-->>Gateway: false
    Gateway->>Gateway: Store message, mark as not validated

    Light Client Relayer->>Light Client Verifier: Relay merkle tree inclusion proof for M

    Relayer->>Gateway: ValidateMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier->>Light Client Verifier: VerifyMessage(M)
    Light Client Verifier-->>Verifier: true
    Verifier-->>Gateway: true
    Gateway->>Gateway: store message, mark as validated

    Relayer->>Gateway: ExecuteMessage(M)
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

    Relayer->>Gateway: ValidateMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier->>Light Client Verifier: VerifyMessage(M)
    Light Client Verifier-->>Verifier: false
    Verifier-->>Gateway: false
    Gateway->>Gateway: Store message, mark as not validated

    Light Client Relayer->>Light Client Verifier: Relay merkle tree inclusion proof for M

    Relayer->>Gateway: ExecuteMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier->>Light Client Verifier: VerifyMessage(M)
    Light Client Verifier-->>Verifier: true
    Verifier-->>Gateway: true
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
    Gateway->>Verifier: VerifyMessage(M)
    Verifier->>Light Client Verifier: VerifyMessage(M)
    Light Client Verifier-->>Verifier: false
    Verifier-->>Gateway: false

    Light Client Relayer->>Light Client Verifier: Relay merkle tree inclusion proof for M

    Relayer->>Gateway: ExecuteMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier->>Light Client Verifier: VerifyMessage(M)
    Light Client Verifier-->>Verifier: true
    Verifier-->>Gateway: true
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

    Relayer->>Gateway: ValidateMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier->>Light Client Verifier: VerifyMessage(M)
    Light Client Verifier-->>Verifier: true
    Verifier-->>Gateway: true
    Gateway->>Gateway: store message, mark as validated

    Relayer->>Gateway: ExecuteMessage(M)
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


    Relayer->>Gateway: ExecuteMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier->>Light Client Verifier: VerifyMessage(M)
    Light Client Verifier-->>Verifier: true
    Verifier-->>Gateway: true
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
    Light Client Verifier-->>Verifier: false
    Verifier-->>Gateway: false
    Gateway->>Gateway: Store message, mark as not validated

    Light Client Relayer->>Light Client Verifier: Relay block header
    Light Client Relayer->>Light Client Verifier: Relay merkle tree inclusion proof for M

    Relayer->>Gateway: ValidateMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier->>Light Client Verifier: VerifyMessage(M)
    Light Client Verifier-->>Verifier: true
    Verifier-->>Gateway: true
    Gateway->>Gateway: store message, mark as validated

    Relayer->>Gateway: ExecuteMessage(M)
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
    Light Client Verifier-->>Verifier: false
    Verifier-->>Gateway: false

    Light Client Relayer->>Light Client Verifier: Relay block header
    Light Client Relayer->>Light Client Verifier: Relay merkle tree inclusion proof for M

    Relayer->>Gateway: ExecuteMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier->>Light Client Verifier: VerifyMessage(M)
    Light Client Verifier-->>Verifier: true
    Verifier-->>Gateway: true
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
    Relayer->>Gateway: ValidateMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier->>Light Client Verifier: VerifyMessage(M)
    Light Client Verifier-->>Verifier: true
    Verifier->>Voting Verifier: VerifyMessage(M)
    Voting Verifier-->>Verifier: false
    Verifier-->>Gateway: false
    Gateway->>Gateway: Store message, mark as not validated

    OffChain Voting Worker->>Voting Verifier: StartPoll
    OffChain Voting Worker->>Voting Verifier: Vote
    OffChain Voting Worker->>Voting Verifier: Vote
    OffChain Voting Worker->>Voting Verifier: EndPoll


    Relayer->>Gateway: ValidateMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier->>Light Client Verifier: VerifyMessage(M) (could be cached from earlier call)
    Light Client Verifier-->>Verifier: true
    Verifier->>Voting Verifier: VerifyMessage(M)
    Voting Verifier-->>Verifier: true
    Verifier-->>Gateway: true
    Gateway->>Gateway: store message, mark as validated

    Relayer->>Gateway: ExecuteMessage(M)
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
    Light Client Verifier-->>Verifier: false
    Verifier->>Voting Verifier: VerifyMessage(M)
    Voting Verifier-->>Verifier: false
    Verifier-->>Gateway: false
    Gateway->>Gateway: Store message, mark as not validated

    Light Client Relayer->>Light Client Verifier: Relay merkle tree inclusion proof for M

    OffChain Voting Worker->>Voting Verifier: StartPoll
    OffChain Voting Worker->>Voting Verifier: Vote
    OffChain Voting Worker->>Voting Verifier: Vote
    OffChain Voting Worker->>Voting Verifier: EndPoll


    Relayer->>Gateway: ValidateMessage(M)
    Gateway->>Verifier: VerifyMessage(M)
    Verifier->>Light Client Verifier: VerifyMessage(M)
    Light Client Verifier-->>Verifier: true
    Verifier->>Voting Verifier: VerifyMessage(M)
    Voting Verifier-->>Verifier: true
    Verifier-->>Gateway: true
    Gateway->>Gateway: store message, mark as validated

    Relayer->>Gateway: ExecuteMessage(M)
    Gateway->>Router: RouteMessage(M)
```






