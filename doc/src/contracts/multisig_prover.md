# Multisig prover contract

The prover contract is responsible for transforming gateway messages into a command batch that is ready to be sent to the destination gateway. It calls the multisig contract to generate the signature proof and finally encodes both the data and proof so that relayers can take it and send it to the destination chain gateway.

## Interface

```Rust
pub enum ExecuteMsg {
    // Start building a proof that includes specified messages
    // Queries the gateway for actual message contents
    ConstructProof {
        message_ids: Vec<String>,
    },
    UpdateWorkerSet,
    ConfirmWorkerSet,
}

#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(GetProofResponse)]
    GetProof { multisig_session_id: Uint64 },

    #[returns(multisig::worker_set::WorkerSet)]
    GetWorkerSet,
}

pub enum ProofStatus {
    Pending,
    Completed { execute_data: HexBinary }, // encoded data and proof sent to destination gateway
}

pub struct GetProofResponse {
    pub multisig_session_id: Uint64,
    pub message_ids: Vec<String>,
    pub data: Data,
    pub status: ProofStatus,
}
```

## Events

```Rust
pub enum Event {
    ProofUnderConstruction {
        command_batch_id: BatchID,
        multisig_session_id: Uint64,
    },
}
```

<br>

## Proof construction graph

```mermaid
graph TD

r[Relayer]
subgraph Axelar
b[Prover]
g[Gateway]
m[Multisig]
end
s[Signer]

r--ConstructProof-->b
b--GetMessages-->g
g-.->b
b--StartSigningSession-->m
b--GetSigningSession-->m
s--SubmitSignature-->m
```

## Proof construction sequence diagram

```mermaid
sequenceDiagram
autonumber
participant Relayer
box LightYellow Axelar
participant Prover
participant Gateway
participant Multisig
end
actor Signers

Relayer->>+Prover: ExecuteMsg::ConstructProof
alt batch not created previously
  Prover->>+Gateway: QueryMsg::GetMessages
  Gateway-->>-Prover: query result
  alt newer WorkerSet exists
    Prover->>Prover: update next WorkerSet
  end
else previously created batch found
  Prover->>Prover: retrieves batch from storage
end
Prover->>+Multisig: ExecuteMsg::StartSigningSession
Multisig-->>Signers: emit SigningStarted event
Multisig->>-Prover: reply with session ID
Prover-->>Relayer: emit ProofUnderConstruction event
deactivate Prover
loop Collect signatures
	Signers->>+Multisig: signature collection
end
Multisig-->>-Relayer: emit SigningCompleted event
Relayer->>+Prover: QueryMsg::GetProof
Prover->>+Multisig: QueryMsg::GetSigningSession
Multisig-->>-Prover: reply with status, current signatures vector and snapshot
Prover-->>-Relayer: returns GetProofResponse
```

1. Relayer asks Prover contract to construct proof providing a list of messages IDs
2. If no batch for the given messages was previously created, it queries the gateway for the messages to construct it
3. With the retrieved messages, the Prover contract transforms them into a batch of commands and generates the binary message that needs to be signed by the multisig.
4. If a newer `WorkerSet` was found, a `TransferOperatorship` command is added to the batch. The new `WorkerSet` is stored as the next `WorkerSet`.
5. If previous batch was found for the given messages IDs, the Prover retrieves it from storage instead of querying the gateway and build it again.
6. The Multisig contract is called asking to sign the binary message
7. Multisig emits event `SigningStarted` indicating a new multisig session has started
8. Multisig triggers a reply in Prover returning the newly created session ID which is then stored with the batch for reference
9. Prover contract emits event `ProofUnderConstruction` which includes the ID of the proof being constructed.
10. Signers submit their signatures until threshold is reached
11. Multisig emits event indicating the multisig session has been completed
12. Relayer queries Prover for the proof, using the proof ID
13. Prover queries Multisig for the multisig session, using the session ID
14. Multisig replies with the multisig state, the list of collected signatures so far and the snapshot of participants.
15. If the Multisig state is `Completed`, the Prover finalizes constructing the proof and returns the `GetProofResponse` struct which includes the proof itself and the data to be sent to the destination gateway. If the state is not completed, the Prover returns the `GetProofResponse` struct with the `status` field set to `Pending`.

## Update and confirm WorkerSet graph

```mermaid
graph TD

r[Relayer]
subgraph Axelar
b[Prover]
v[Voting Verifier]
m[Multisig]
s[Service Registry]
end

r--UpdateWorkerSet-->b
b--GetActiveWorkers-->s
b--RegisterWorkerSet-->m
r--ConfirmWorkerSet-->b
b--IsWorkerSetVerified-->v
```

## Update and confirm WorkerSet sequence diagram

```mermaid
sequenceDiagram
autonumber
participant External Gateway
participant Relayer
box LightYellow Axelar
participant Prover
participant Service Registry
participant Voting Verifier
participant Multisig
end
actor Worker
actor Signers
Relayer->>+Prover: ExecuteMsg::UpdateWorkerSet
alt existing WorkerSet stored
  Prover->>+Service Registry: QueryMsg::GetActiveWorkers
  Service Registry-->>-Prover: save new WorkerSet as next WorkerSet
  Prover->>+Multisig: ExecuteMsg::StartSigningSession (for operatorship transferred message)
  loop Collect signatures
	  Signers->>+Multisig: signature collection
  end
end
Relayer->>+Prover: QueryMsg::GetProof
Prover-->>-Relayer: returns GetProofResponse (new worker set signed by old worker set)
Relayer-->>External Gateway: send new WorkerSet to the gateway, signed by old WorkerSet
External Gateway-->>+Relayer: emit OperatorshipTransferred event
Relayer->>+Voting Verifier: ExecuteMsg::VerifyWorkerSet
Worker->>+External Gateway: lookup OperatorshipTransferred event, verify event matches worker set in poll
Worker->>+Voting Verifier: ExecuteMsg::Vote
Relayer->>+Voting Verifier: ExecuteMsg::EndPoll
Relayer->>+Prover: ExecuteMsg::ConfirmWorkerSet
Prover->>+Voting Verifier: QueryMsg::IsWorkerSetVerified
Voting Verifier-->>-Prover: true
Prover->>+Multisig: ExecuteMsg::RegisterWorkerSet
```

1. The Relayer calls Prover to update the `WorkerSet`.
2. The Prover calls Service Registry to get a `WorkerSet`
3. If a newer `WorkerSet` was found, the new `WorkerSet` is stored as the next `WorkerSet`. A `TransferOperatorship` command is added to the batch.
4. The Multisig contract is called asking to sign the binary message
5. Signers submit their signatures until threshold is reached
6. Relayer queries Prover for the proof, using the proof ID
7. If the Multisig state is `Completed`, the Prover finalizes constructing the proof and returns the `GetProofResponse` struct which includes the proof itself and the data to be sent to the External Chain's gateway. If the state is not completed, the Prover returns the `GetProofResponse` struct with the `status` field set to `Pending`.
8. Relayer sends proof and data to the External Gateway.
9. The gateway on the External Gateway proccesses the commands in the data and emits event `OperatorshipTransferred`.
10. The event `OperatorshipTransferred` picked up by the Relayer, the Relayer calls Voting Verifier to create a poll.
11. The Workers see the `PollStarted` event and lookup `OperatorshipTransferred`` event on the External Gateway and verify event matches worker set in poll.
12. The Workers then vote on whether the event matches the workers or not.
13. The Relayer calls the Voting Verifier to end the poll and emit `PollEnded` event.
14. Once the poll is completed, the Relayer calls the Prover to confirm if the `WorkerSet` was updated.
15. The Prover queries the Voting Verifier to check if the `WorkerSet` is confirmed.
16. The Voting Verifier returns that the `WorkerSet` is confirmed.
17. The Prover stores the `WorkerSet` in itself and in Multisig.
