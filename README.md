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
Incoming Flow:
```mermaid
flowchart TD
subgraph Axelar
	G1{"Gateway"}
    G2{"Gateway"}
	Vr{"Aggregate Verifier"}
	Vo{"Voting verifier"}
	R{"Router"}
    S{"Service Registry"}
end

Relayer --"VerifyMessages([M1,M2])"-->G1
G1 --"VerifyMessages([M1,M2])"--> Vr
Vr --"VerifyMessages([M1,M2])"--> Vo
Vo --"GetBondedWorkers"--> S
Validators --"Vote(poll_id, votes)"--> Vo

Relayer --"RouteMessages([M1,M2])"-->G1
G1 --"RouteMessages([M1,M2])"-->R
R --"RouteMessages([M1,M2])"-->G2
```
Outgoing Flow:
```mermaid
flowchart TD
subgraph Axelar
    G2{"Gateway"}
    P{"Prover"}
    M{"Multisig"}
    S{"Service Registry"}
end
Signers

Relayer --"ConstructProof([M1.id,M2.id])"-->P
P --"GetMessages([M1.id,M2.id])"-->G2
P --"GetBondedWorkers"-->S
P --"StartSigningSession(key_id, batch_hash)"-->M
Signers --"SubmitSignature(session_id, signature)"-->M
Relayer --"GetProof(proof_id)" --> P
P --"GetSigningSession(session_id)"-->M
```

# Event Flow

In the below diagram, the blue box represents the protocol. All messages flowing into, out of or within the blue box
are part of the protocol. All components within the blue box are on chain. All components outside of the blue box are off chain.

## Voting Contract Flows
Incoming Message Flow
```mermaid
sequenceDiagram
    participant Relayer
    box Blue Protocol
    participant IncomingGateway
    participant Router
    participant Verifier
    participant Prover
    participant Voting Verifier
    participant Service Registry
    end
    participant OffChain Voting Worker
    Relayer->>IncomingGateway: VerifyMessages([M1,M2])
    IncomingGateway->>Verifier: VerifyMessages([M1,M2])
    Verifier->>Voting Verifier: VerifyMessages([M1,M2])
    Voting Verifier->>Service Registry: GetBondedWorkers
    Voting Verifier->>OffChain Voting Worker: emit PollStarted
    Voting Verifier-->>Verifier: [(M1.id,false),(M2.id,false)]
    Verifier-->>IncomingGateway: [(M1.id,false),(M2.id, false)]
    IncomingGateway-->>Relayer: [(M1.id,false),(M2.id, false)]
    OffChain Voting Worker->>Voting Verifier: Vote
    OffChain Voting Worker->>Voting Verifier: Vote
    OffChain Voting Worker->>Voting Verifier: EndPoll



    Relayer->>IncomingGateway: RouteMessages([M1,M2])
    IncomingGateway->>Verifier: IsVerified([M1,M2])
    Verifier->>Voting Verifier: IsVerified([M1,M2])
    Voting Verifier->>Verifier: [(M1.id,true),(M2.id,true)]
    Verifier->>IncomingGateway: [(M1.id,true),(M2.id,true)]
    IncomingGateway->>Router: RouteMessages([M1,M2])

```


Outgoing Message Flow
```mermaid
sequenceDiagram
    participant Relayer
    box Blue Protocol
    participant OutgoingGateway
    participant Router
    participant Prover
    participant Multisig
    end
    participant Signer


    Router->>OutgoingGateway: RouteMessages([M1,M2])
    Relayer->>Prover: ConstructProof([M1.id,M2.id])
    Prover->>OutgoingGateway: GetMessages([M1,M2])
    OutgoingGateway-->>Prover: [M1,M2]
    Prover->>Prover: create batch of [M1,M2]
    Prover->>Multisig: StartSigningSession(snapshot, batch hash)
    Multisig-->>Prover: session_id
    Prover-->>Relayer: proof_id
    Signer->>Multisig: SubmitSignature(session_id, signature)
    Signer->>Multisig: SubmitSignature(session_id, signature)
    Relayer->>Prover: GetProof(proof_id)
    Prover->>Multisig: GetSigningSession(session_id)
    Multisig-->>Prover: signing session
    Prover-->>Relayer: signed batch

```

Prover stores the snapshot of the current signers and passes the snapshot to the multisig contract.
Periodically, the stored snapshot is rotated by the prover controller, which triggers the prover to
query the service registry for an updated snapshot.
