# Voting Verifier

The voting verifier verifies batches of messages via RPC voting. Polls are created and votes are cast via a generic voting module,
which the voting verifier uses. The generic voting module does not know the meaning of the polls, and simply returns a poll
poll ID to the voting verifier. The voting verifier internally maps
a poll ID to the messages in the poll, to be able to call back to
the verifier and propagate the result back to the gateway.



```mermaid
flowchart TD
subgraph Axelar
    G{"Gateway"}
    Vr{"Voting Verifier"}
    V{"Verifier"}
    R{"Service Registry"}
end
OC{"Off-Chain Procceses"}

G--"VerifyMessages([M, M', M''])"-->V
V--"VerifyMessages([M, M', M''])"-->Vr
OC --"StartPoll([M, M', M''])"-->Vr
Vr--"GetActiveWorkers"-->R
OC--"Vote(poll_id, votes)"-->Vr
OC--"EndPoll(poll_id)"-->Vr
Vr--"MessagesVerified([M,M',M''])"-->V

```

```mermaid
sequenceDiagram
participant Verifier
participant Voting Verifier
participant Service Registry
participant OC as Off-Chain Processes


Verifier->>Voting Verifier: VerifyMessages([M,M',M''])

Voting Verifier->>Voting Verifier: StartPoll([M,M',M''])
Voting Verifier->>Service Registry: GetActiveWorkers
Service Registry-->>Voting Verifier: list of workers and stake
Voting Verifier->>OC: emit event with poll_id and messages
Voting Verifier-->>Verifier: [false,false,false]

OC->>Voting Verifier: Vote(poll_id, votes)
OC->>Voting Verifier: Vote(poll_id, votes)

OC->>Voting Verifier: EndPoll(poll_id)
Voting Verifier->>Verifier: MessagesVerified([M,M',M''])


```
