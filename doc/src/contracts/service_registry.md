# Service Registry

The service registry keeps track of the pool of workers that vote and sign for each chain.
The core functionalities, such as registering a new service, worker authorization and un-authorization can only be
called
from a governance address. Worker bonding and unbonding, as well as registering support for specific chains, are called
by the worker themselves.
To become active and be eligible to participate in voting for a specific chain,
each worker should first be authorized and bond enough stake, and then register support for that chain.
Service registry is used by ampd, verifier, and multisig prover.

The term `service` refers to an upper-level entity that includes several
`chains`. The difference is in how they are related to each other, which is
hierarchical; a service is like an umbrella that regulates the activities of
several chains that fall under its purview. The service defines common
parameters, such as worker requirements, bonding details, and unbonding periods, which are applicable to all associated
chains.
Thus, we use a single instance of service registry to organize and coordinate activities across all chains.

## Interface

```Rust
pub enum ExecuteMsg {
    // Can only be called by governance account
    RegisterService {
        service_name: String,
        service_contract: Addr,
        min_num_workers: u16,
        max_num_workers: Option<u16>,
        min_worker_bond: Uint128,
        bond_denom: String,
        unbonding_period_days: u16,
        description: String,
    },
    // Authorizes workers to join a service. Can only be called by governance account. Workers must still bond sufficient stake to participate.
    AuthorizeWorkers {
        workers: Vec<String>,
        service_name: String,
    },
    // Revoke authorization for specified workers. Can only be called by governance account. Workers bond remains unchanged
    UnauthorizeWorkers {
        workers: Vec<String>,
        service_name: String,
    },

    // Register support for the specified chains. Called by the worker.
    RegisterChainSupport {
        service_name: String,
        chains: Vec<ChainName>,
    },
    // Deregister support for the specified chains. Called by the worker.
    DeregisterChainSupport {
        service_name: String,
        chains: Vec<ChainName>,
    },

    // Locks up any funds sent with the message as stake. Called by the worker.
    BondWorker {
        service_name: String,
    },
    // Initiates unbonding of staked funds. Called by the worker.
    UnbondWorker {
        service_name: String,
    },
    // Claim previously staked funds that have finished unbonding. Called by the worker.
    ClaimStake {
        service_name: String,
    },
}

```

## Service Registry graph

```mermaid
flowchart TD
subgraph Axelar
    Vr{"Voting Verifier"}
    R{"Service Registry"}
end
OC{"Workers"}

Vr -- "GetActiveWorkers" --> R
OC -- "De/RegisterChainSupport" --> R
OC -- "Un/BondWorker" --> R
OC -- "ClaimStake" --> R
```

## Service Registry sequence diagram

```mermaid
sequenceDiagram
autonumber
box LightYellow Axelar
    participant Service Registry
end
actor Governance
actor Worker

Governance->>+Service Registry: Register Service
Governance->>+Service Registry: Authorize Workers

Worker->>+Service Registry: Bond Worker
Worker->>+Service Registry: Register Chain Support

```

1. The Governance registers a new service by providing the necessary parameters for the service.
2. Governance is also responsible for authorizing workers to join the service by sending an `Authorize Workers` message.
3. Workers bond to the service, providing stake, by sending a `Bond Worker` message with appropriate funds included.
   Note that authorizing and bonding can be done in any order.
4. Workers register support for specific chains within the service by specifying service name and chain names.

### Notes

1. For the process of signing, workers need to register their public key in advance to be able to participate,
   the details of which are available in [`multisig documentation`](multisig.md).
