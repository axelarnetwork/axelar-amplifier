# Access Control for Contract Messages
This module provides access control for contract execute messages. An execute message can be called by:
- Anyone
- Only by governance
- Only by the contract admin
- Either governance or the contract admin
- Either governance or coordinator contract

Only contracts that have at least one execute message with restricted access are included in this module.

## Router

### Governance or Coordinator Contract
```rust
RegisterChain {
    chain: ChainName,
    gateway_address: Address,
    msg_id_format: MessageIdFormat,
},

```
### Governance-Only
```rust
UpgradeGateway {
    chain: ChainName,
    contract_address: Address,
},
```

### Admin or Governance
```rust
FreezeChains {
    chains: HashMap<ChainName, GatewayDirection>
},

UnfreezeChains {
    chains: HashMap<ChainName, GatewayDirection>
},

DisableRouting,

EnableRouting
```


## Voting Verifier

### Governance-Only
```rust
UpdateVotingThreshold {
    new_voting_threshold: MajorityThreshold,
}
```


## Prover

### Governance-Only
```rust
UpdateSigningThreshold {
    new_signing_threshold: MajorityThreshold,
},

UpdateAdmin {
    new_admin_address: String,
}
```

### Admin or Governance
```rust
UpdateVerifierSet
```


## Multisig

### Governance or Coordinator Contract
```rust
AuthorizeCallers {
        contracts: HashMap<String, ChainName>,
},
```
### Governance or Admin

```rust
UnauthorizeCallers {
        contracts: HashMap<String, ChainName>,
},
DisableSigning,
EnableSigning
```

### Authorized Caller Only
Authorized caller is any contract that is previously authorized from governance by calling `AuthorizeCaller`. 
```rust
StartSigningSession { // Can only be called by an authorized contract
    verifier_set_id: String,
    msg: HexBinary,
    chain_name: ChainName,
    sig_verifier: Option<String>,
}
```


## Service Registry

### Governance-Only
```rust
RegisterService {
    service_name: String,
    coordinator_contract: String,
    min_num_verifiers: u16,
    max_num_verifiers: Option<u16>,
    min_verifier_bond: nonempty::Uint128,
    bond_denom: String,
    unbonding_period_days: u16,
    description: String,
},
UpdateService {
        service_name: String,
        updated_service_params: UpdatedServiceParams,
},

OverrideServiceParams {
        service_name: String,
        chain_name: ChainName,
        service_params_override: ServiceParamsOverride,
},

RemoveServiceParamsOverride {
        service_name: String,
        chain_name: ChainName,
},

AuthorizeVerifiers {
    verifiers: Vec<String>,
    service_name: String,
},

UnauthorizeVerifiers {
    verifiers: Vec<String>,
    service_name: String,
},

JailVerifiers {
    verifiers: Vec<String>,
    service_name: String,
}
```


## Coordinator

### Governance-Only
```rust
RegisterProtocol {
        service_registry_address: String,
        router_address: String,
        multisig_address: String,
},
RegisterChain {
        chain_name: ChainName,
        prover_address: String,
        gateway_address: String,
        voting_verifier_address: String,
},
InstantiateChainContracts {
        deployment_name: nonempty::String,
        salt: Binary,
        params: Box<DeploymentParams>,
},
RegisterDeployment { deployment_name: nonempty::String },
```

### Registered Prover Only 
A registered prover is a contract address that was previously registered by governance for a specific chain via the `RegisterChain` message.
```rust
SetActiveVerifiers { verifiers: HashSet<String> },
```
