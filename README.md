# axelar-service-registry
# Message Semantics
Structure of a routing packet (`M` in the diagrams)
```rust
    struct Message {
        id: String,
        source_address: String,
        source_chain: String,
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
Vo --"MessageVerified(M)"--> Vr
Vr --"VerifyMessage(M)"--> Lc
Lc --"MessageVerified(M)"--> Vr
Vr --"MessageVerified(M)"--> G

Relayer --"ExecuteMessage(M)"-->G
G --"RouteMessage(M)"-->R
```
As an optimization `VerifyMessage(M)` can be replaced with `VerifyMessage(M.id, hash(M))`

# Event Flow

In all of the below flows, the specifics of how an individual verification method works (voting verifier or light client verifier)
is not important and is not part of this design. They are merely shown as examples. Each specific verification method 
just needs to accept `VerifyMessage` calls, and return true or false. Each specific verification method is free to
add additional methods and queries to its interface, to be called by associated worker processes or contracts (that could be on or off chain). 

In the below flows, the blue box represents the protocol. All messages flowing into, out of or within the blue box
are part of the protocol.

## Voting Contract Flows
ValidateMessage -> Poll -> ExecuteMessage
```mermaid
sequenceDiagram
    participant Relayer
    box Blue Protocol
    participant Gateway
    participant Verifier
    participant Router
    end
    participant Voting Verifier
    participant OffChain Voting Worker
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
    box Blue Protocol
    participant Gateway
    participant Verifier
    participant Router
    end
    participant Voting Verifier
    participant OffChain Voting Worker
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
    box Blue Protocol
    participant Gateway
    participant Verifier
    participant Router
    end
    participant Voting Verifier
    participant OffChain Voting Worker
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
    box Blue Protocol
    participant Gateway
    participant Verifier
    participant Router
    end
    participant Voting Verifier
    participant OffChain Voting Worker

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
    box Blue Protocol
    participant Gateway
    participant Verifier
    participant Router
    end
    participant Light Client Verifier
    participant Light Client Relayer

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
    Gateway->>Relayer: emit message verified event
    Verifier->>Light Client Verifier: VerifyMessage(M)
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

    box Blue Protocol
    participant Gateway
    participant Verifier
    participant Router
    end

    participant Light Client Verifier
    participant Light Client Relayer

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
    box Blue Protocol
    participant Gateway
    participant Verifier
    participant Router
    end
    participant Light Client Verifier
    participant Light Client Relayer

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
    box Blue Protocol
    participant Gateway
    participant Verifier
    participant Router
    end
    participant Light Client Verifier
    participant Light Client Relayer

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
    box Blue Protocol
    participant Gateway
    participant Verifier
    participant Router
    end
    participant Light Client Verifier
    participant Light Client Relayer


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
    box Blue Protocol
    participant Gateway
    participant Verifier
    participant Router
    end
    participant Light Client Verifier
    participant Light Client Relayer


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
    box Blue Protocol
    participant Gateway
    participant Verifier
    participant Router
    end
    participant Light Client Verifier
    participant Voting Verifier
    participant Light Client Relayer
    participant OffChain Voting Worker


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
    box Blue Protocol
    participant Gateway
    participant Verifier
    participant Router
    end
    participant Light Client Verifier
    participant Voting Verifier
    participant Light Client Relayer
    participant OffChain Voting Worker


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



