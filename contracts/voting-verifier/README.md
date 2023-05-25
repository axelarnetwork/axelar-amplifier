# Voting Verifier

The voting verifier verifies batches of messages via RPC voting. Polls are created and votes are cast via a generic voting contract,
which the voting verifier talks to. The generic voting contract does not know the meaning of the polls, and simply returns a poll
poll ID to the voting verifier. The voting verifier internally maps
a poll ID to the messages in the poll, to be able to call back to
the verifier and propagate the result back to the gateway.



```mermaid
flowchart TD
subgraph Axelar
    G{"Gateway"}
    Vr{"Voting Verifier"}
    Vg{"Generic voting contract"}
    V{"Verifier"}
    R{"Service Registry"}
end
G--"VerifyMessages([M, M', M''])"-->V
V--"VerifyMessages([M, M', M''])"-->Vr
Workers --"StartPoll([M, M', M''])"-->Vr
Vr--"GetActiveWorkers"-->R
Vr--"StartPoll(workers)"-->Vg
Workers--"Vote(poll_id, votes)"-->Vg
Workers--"EndPoll(poll_id)"-->Vr
Vr--"EndPoll(poll_id)"-->Vg
Vr--"MessagesVerified([M,M',M''])"-->V

```

```mermaid
sequenceDiagram
participant Verifier
participant Voting Verifier
participant Generic Voting Contract
participant Service Registry
participant Workers

Verifier->>Voting Verifier: VerifyMessages([M,M',M''])
Voting Verifier->>Voting Verifier: StartPoll([M,M',M''])


Voting Verifier->>Service Registry: GetActiveWorkers
Service Registry-->>Voting Verifier: list of workers and stake
Voting Verifier->>Generic Voting Contract: StartPoll(workers)
Generic Voting Contract-->>Voting Verifier: poll_id
Voting Verifier->>Workers: emit event with poll_id and messages
Voting Verifier-->>Verifier: [false,false,false]

Workers->>Generic Voting Contract: Vote(poll_id, votes)
Workers->>Generic Voting Contract: Vote(poll_id, votes)

Workers->>Voting Verifier: EndPoll(poll_id)
Voting Verifier->>Generic Voting Contract: EndPoll(poll_id)
Generic Voting Contract-->>Voting Verifier: poll result

Voting Verifier->>Verifier: MessagesVerified([M,M',M''])


```