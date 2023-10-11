## Rewards

```mermaid
graph LR
V[Voting Verifier]
M[Multisig]
R[Rewards]
E[EndBlocker]
U[User]
W[Workers]
G[Governance]

V--RecordParticipation-->R
M--RecordParticipation-->R
E--DistributeRewards-->R
U--AddRewards-->R
G--UpdateParams-->R
R--Send rewards-->W
```

The rewards contract is responsible for tracking worker participation in voting and signing.
The voting verifier and multisig contract send messages to the rewards contract when workers
participate in events. The rewards contract keeps a tally of how many events each worker
participated in. Participation is assessed per epoch, which is a length of time configurable
by governance. Calling `DistributeRewards` distributes rewards for the epoch two epochs prior to the current epoch,
(so if we are in epoch 2, we distribute rewards for epoch 0). Rewards are split equally amongst
all participating validators in the epoch. The rewards rate (number of tokens distributed per epoch)
is configurable by governance. Anyone can add funds to the rewards pool by calling `AddRewards`. 
Anyone can call `DistributeRewards` and trigger rewards distribution, but it is designed to be called
automatically by the end blocker.

### Voting Flow
```mermaid
sequenceDiagram
participant Rewards
participant VotingVerifier
participant Workers
participant Gateway
participant Relayer

Relayer ->> Gateway: VerifyMessages
Gateway ->> VotingVerifier: VerifyMessages
Worker ->> VotingVerifier: Vote
Relayer ->> VotingVerifier: EndPoll
loop For each validator who voted correctly
Worker ->> Rewards: RecordParticipation
end
Worker ->> VotingVerifier: Vote
opt If voted within grace period and voted correctly
VotingVerifier ->> Rewards: RecordParticipation
end
```

### Signing Flow
```mermaid

sequenceDiagram
participant Rewards
participant Multisig
participant Worker
participant Multisig Prover

Multisig Prover ->> Multisig: StartSigningSession
Worker ->> Multisig: Sign
opt If signed within grace period
Multisig ->> Rewards: RecordParticipation
end
```
