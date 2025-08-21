# Voting Verifier

The voting verifier verifies batches of messages via RPC voting. Polls are created and votes are cast via a generic
voting module,
which the voting verifier uses. The generic voting module does not know the meaning of the Polls, and simply returns a
Poll ID to the voting verifier. The voting verifier internally maps
a Poll ID to the messages in the Poll, storing the results in the storage. The gateway can then query the voting verifier to check message verification status.

There are two types of polls: messages polls and verifier set polls. Messages polls are used to verify incoming
messages,
while verifier set polls are used to verify that the external gateway has updated its stored verifier set. Verifier set
polls
are a necessary component of the verifier set update flow.
See [`update and confirm VerifierSet sequence diagram`](multisig_prover.md)
for more details.

## Verifier graph

```mermaid
flowchart TD
subgraph Axelar
    G{"Gateway"}
    Vr{"Voting Verifier"}
    V{"Verifier"}
    R{"Service Registry"}
end
OC{"Verifiers"}

G--"VerifyMessages([M, M', M''])"-->V
V--"VerifyMessages([M, M', M''])"-->Vr
Vr--"ActiveVerifiers"-->R
OC--"Vote(poll_id, votes)"-->Vr
OC--"EndPoll(poll_id)"-->Vr
Vr--"MessagesVerified([M,M',M''])"-->V

```

## Message Verification Sequence Diagram

```mermaid
sequenceDiagram
participant Gateway
participant Voting Verifier
participant Service Registry
participant OC as Verifiers


Gateway->>Voting Verifier: VerifyMessages([M,M',M''])

Voting Verifier->>Service Registry: ActiveVerifiers
Service Registry-->>Voting Verifier: list of verifiers and stake
Voting Verifier->>OC: emit event with poll_id and messages
Voting Verifier-->>Verifier: [false,false,false]

OC->>Voting Verifier: Vote(poll_id, votes)
OC->>Voting Verifier: Vote(poll_id, votes)

OC ->>Voting Verifier: EndPoll(poll_id)
note right of Voting Verifier: Poll results are now stored.

opt After poll has ended
    Gateway->>Voting Verifier: query MessagesStatus([M,M',M''])
    Voting Verifier-->>Gateway: return [MessageStatus, ...]
end

```
