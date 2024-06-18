# Contract Messages with Special Access Needs
Only those contracts that has at least one execute message with restricted access are included in this part.

## Router

### Governance-Only Messages
```rust
RegisterChain {
    chain: ChainName,
    gateway_address: Address,
    msg_id_format: MessageIdFormat,
},

UpgradeGateway {
    chain: ChainName,
    contract_address: Address,
},
```

### Admin-Only Messages
```rust
FreezeChain {
    chain: ChainName,
    direction: GatewayDirection,
},

UnfreezeChain {
    chain: ChainName,
    direction: GatewayDirection,
},
```


## Verifier

### Governance-Only Messages
```rust
UpdateVotingThreshold {
    new_voting_threshold: MajorityThreshold,
},
```


## Prover

### Governance-Only Messages
```rust
UpdateSigningThreshold {
    new_signing_threshold: MajorityThreshold,
},

UpdateAdmin {
    new_admin_address: String,
},
```

### Admin Or Governance Messages
```rust
UpdateVerifierSet,
```


## Multisig

### Governance-Only Messages
```rust
AuthorizeCaller {
    contract_address: Addr,
},

UnauthorizeCaller {
    contract_address: Addr,
},
```

### Authorized Caller Only Messages
```rust
StartSigningSession { // Can only be called by an authorized contract
    verifier_set_id: String,
    msg: HexBinary,
    chain_name: ChainName,
    sig_verifier: Option<String>,
},
```


## Service Registry

### Governance-Only Messages
```rust
RegisterService {
    service_name: String,
    coordinator_contract: Addr,
    min_num_verifiers: u16,
    max_num_verifiers: Option<u16>,
    min_verifier_bond: Uint128,
    bond_denom: String,
    unbonding_period_days: u16, 
    description: String,
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
},
```


## Coordinator

### Governance-Only Messages
```rust
RegisterProverContract {
    chain_name: ChainName,
    new_prover_addr: Addr,
},
```