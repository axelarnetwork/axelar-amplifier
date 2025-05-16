# Coordinator

Some contracts, like the multisig provers, are deployed per chain and unknown to one another.The Coordinator Contract is like a central registry for mapping and coordinating relationships between those chain-specific contracts in the Axelar Amplifier system. 
The coordinator contract keeps track of these chain-dependent provers and coordinates any interaction that requires knowledge of all of them. 
For example, the ability for a verifier to unbond their stake requires to check that it's not part of any active verifier set on any chain.

### Prover Registration and Verifier Management
```mermaid
flowchart TD

Co{"Coordinator"}
Go{"Governance"}
PrA{"Prover A"}
PrB{"Prover B"}
PrC{"Prover C"}


Go -- "Register Prover contract" --> Co
PrA  -- "Set active verifiers" --> Co
PrB  -- "Set active verifiers" --> Co
PrC  -- "Set active verifiers" --> Co
```
The Coordinator Contract acts as a central hub that registers chain-specific prover contracts, manages active verifiers, and routes queries between governance, provers, and other components like the service registry and gateway.

```mermaid
graph TD
    Governance["Governance"]
    MultisigProver["Multisig Prover"]
    Coordinator["Coordinator Contract"]
    VotingVerifier["Voting Verifier"]
    Gateway["Gateway Contract addr"]
    Registry["Service Registry addr"]
    Prover["prover addr"]

    Governance -->|Registers chains and contract addresses| Coordinator
    MultisigProver -->|Sets active verifiers| Coordinator
    MultisigProver -->|query chain contact info| Coordinator
    Coordinator --> |queries verifier info|Registry
    Coordinator --> |maps to| VotingVerifier 
    Coordinator --> |maps to| Gateway 
 Coordinator --> |maps to |Prover 
  
    
```
