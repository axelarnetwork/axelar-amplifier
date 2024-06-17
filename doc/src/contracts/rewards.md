## Rewards

```mermaid
graph LR
V[Voting Verifier]
M[Multisig]
R[Rewards]
E[EndBlocker]
U[User]
W[Verifiers]
G[Governance]

V--RecordParticipation-->R
M--RecordParticipation-->R
E--DistributeRewards-->R
U--AddRewards-->R
G--UpdateParams-->R
R--Send rewards-->W
```

The rewards contract is responsible for tracking verifier participation in voting and signing.
The voting verifier and multisig contract send messages to the rewards contract when verifiers
participate in events. The rewards contract keeps a tally of how many events each verifier
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
participant Verifier
participant Gateway
participant Relayer

Relayer ->> Gateway: VerifyMessages
Gateway ->> VotingVerifier: VerifyMessages
Verifier ->> VotingVerifier: Vote
Relayer ->> VotingVerifier: EndPoll
loop For each validator who voted correctly
Verifier ->> Rewards: RecordParticipation
end
Verifier ->> VotingVerifier: Vote
opt If voted within grace period and voted correctly
VotingVerifier ->> Rewards: RecordParticipation
end
```

### Signing Flow

```mermaid

sequenceDiagram
participant Rewards
participant Multisig
participant Verifier
participant Multisig Prover

Multisig Prover ->> Multisig: StartSigningSession
Verifier ->> Multisig: Sign
opt If signed within grace period
Multisig ->> Rewards: RecordParticipation
end
```
