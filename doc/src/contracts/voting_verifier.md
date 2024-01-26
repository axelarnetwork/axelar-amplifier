# Voting Verifier

The voting verifier verifies batches of messages via RPC voting. Polls are created and votes are cast via a generic voting module,
which the voting verifier uses. The generic voting module does not know the meaning of the Polls, and simply returns a
Poll ID to the voting verifier. The voting verifier internally maps
a Poll ID to the messages in the Poll, to be able to call back to
the verifier and propagate the result back to the gateway.

There are two types of polls: messages polls and worker set polls. Messages polls are used to verify incoming messages, while worker set polls are used to verify that the external gateway has updated it's stored worker set. Worker set polls are a necessary component of the worker set update flow. See [`update and confirm WorkerSet sequence diagram`](multisig_prover.md)
for more details.



## Verfier graph

```mermaid
flowchart TD
subgraph Axelar
    G{"Gateway"}
    Vr{"Voting Verifier"}
    V{"Verifier"}
    R{"Service Registry"}
end
OC{"Workers"}

G--"VerifyMessages([M, M', M''])"-->V
V--"VerifyMessages([M, M', M''])"-->Vr
Vr--"GetActiveWorkers"-->R
OC--"Vote(poll_id, votes)"-->Vr
OC--"EndPoll(poll_id)"-->Vr
Vr--"MessagesVerified([M,M',M''])"-->V

```



## Message Verification Sequence Diagram


```mermaid
sequenceDiagram
participant Verifier
participant Voting Verifier
participant Service Registry
participant OC as Workers


Verifier->>Voting Verifier: VerifyMessages([M,M',M''])

Voting Verifier->>Service Registry: GetActiveWorkers
Service Registry-->>Voting Verifier: list of workers and stake
Voting Verifier->>OC: emit event with poll_id and messages
Voting Verifier-->>Verifier: [false,false,false]

OC->>Voting Verifier: Vote(poll_id, votes)
OC->>Voting Verifier: Vote(poll_id, votes)

OC->>Voting Verifier: EndPoll(poll_id)
Voting Verifier->>Verifier: MessagesVerified([M,M',M''])


```
