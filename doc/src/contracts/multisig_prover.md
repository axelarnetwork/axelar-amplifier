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
    SnapshotRotated {
        key_id: String,
        snapshot: Snapshot,
        pub_keys: HashMap<String, HexBinary>,
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
  Prover->>Prover: update next WorkerSet
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

e[External Chain]
r[Relayer]
subgraph Axelar
b[Prover]
v[Voting Verifier]
m[Multisig]
end
s[Signer]

r--UpdateWorkerSet-->b
b--RegisterWorkerSet-->m
b--StartSigningSession-->m
r--GetProof-->b
b--GetSigningSession-->m
s--SubmitSignature-->m
r-.->e
e-.->r
r--ConfirmWorkerSet-->v
r--EndPoll-->v
r--ConfirmWorkerSet-->b
b--IsWorkerSetConfirmed-->v
```


## Update and confirm WorkerSet sequence diagram

```mermaid
sequenceDiagram
autonumber
participant External Chain
participant Relayer
box LightYellow Axelar
participant Prover
participant Voting Verifier
participant Multisig
end
actor Signers
Relayer->>+Prover: ExecuteMsg::UpdateWorkerSet
alt no WorkerSet stored
  Prover->>Prover: save new WorkerSet
  Prover->>+Multisig: ExecuteMsg::RegisterWorkerSet
  Multisig-->>-Prover: returns Response
  Prover-->>-Relayer: returns Response
else existing WorkerSet stored
  Prover->>Prover: save new WorkerSet as the next WorkerSet
  Prover->>+Multisig: ExecuteMsg::StartSigningSession
  Multisig-->>Signers: emit SigningStarted event
  Multisig->>-Prover: reply with session ID
  Prover-->>Relayer: emit ProofUnderConstruction event
  loop Collect signatures
	  Signers->>+Multisig: signature collection
  end
  Multisig-->>-Relayer: emit SigningCompleted event
  Relayer->>+Prover: QueryMsg::GetProof
  Prover->>+Multisig: QueryMsg::GetSigningSession
  Multisig-->>-Prover: reply with status, current signatures vector and snapshot
  Prover-->>-Relayer: returns GetProofResponse
  Relayer-->>External Chain: send proof and data
  External Chain-->>+Relayer: emit OperatorshipTransferred event
  Relayer->>+Voting Verifier: ExecuteMsg::ConfirmWorkerSet
  Voting Verifier-->>-Relayer: returns Response
  Relayer->>+Voting Verifier: ExecuteMsg::EndPoll
  Voting Verifier-->>-Relayer: emit PollEnded event
  Relayer->>+Prover: ExecuteMsg::ConfirmWorkerSet
  Prover->>+Voting Verifier: QueryMsg::IsWorkerSetConfirmed
  Voting Verifier-->>-Prover: query result
  Prover->>+Multisig: ExecuteMsg::RegisterWorkerSet
  Multisig-->>-Prover: returns Response
  Prover-->>-Relayer: returns Response
end
```

1. The Relayer calls Prover to update the `WorkerSet`.
2. Replaces the current `WorkerSet` by saving the new `WorkerSet`.
3. The new `WorkerSet` is also saved in Multisig.
4. Default Response is returned from Multisig.
5. Response is returned from Prover.
6. If a newer `WorkerSet` was found, a `TransferOperatorship` command is added to the batch. The new `WorkerSet` is stored as the next `WorkerSet`.
7. The Multisig contract is called asking to sign the binary message
8. Multisig emits event `SigningStarted` indicating a new multisig session has started
9. Multisig triggers a reply in Prover returning the newly created session ID which is then stored with the batch for reference
10. Prover contract emits event `ProofUnderConstruction` which includes the ID of the proof being constructed.
11. Signers submit their signatures until threshold is reached
12. Multisig emits event indicating the multisig session has been completed
13. Relayer queries Prover for the proof, using the proof ID
14. Prover queries Multisig for the multisig session, using the session ID
15. Multisig replies with the multisig state, the list of collected signatures so far and the snapshot of participants.
16. If the Multisig state is `Completed`, the Prover finalizes constructing the proof and returns the `GetProofResponse` struct which includes the proof itself and the data to be sent to the External Chain's gateway. If the state is not completed, the Prover returns the `GetProofResponse` struct with the `status` field set to `Pending`.
17. Relayer sends proof and data to the external chain.
18. The gateway on the External Chain proccesses the commands in the data and emits event `OperatorshipTransferred`.
19. The event `OperatorshipTransferred` picked up by the Relayer, the Relayer calls Voting Verifier to create a poll. 
20. Default Response is returned.
21. The Relayer calls the Voting Verifier to end the poll.
22. The Voting Verifier emits event `PollEnded`.
23. Once the poll is completed, the Relayer calls the Prover to confirm if the `WorkerSet` was updated.
24. The Prover queries the Voting Verifier to check if the `WorkerSet` is confirmed.
25. The Voting Verifier returns if the `WorkerSet` is confirmed. If true, the `Prover` stores the `WorkerSet`.
26. The new `WorkerSet` is stored in Multisig.
27. Default response is returned.
28. Response is returned.
