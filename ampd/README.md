# Ampd

Ampd is the off chain daemon responsible for voting and signing within the amplifier protocol.
The daemon listens to the Axelar blockchain for specific events, connects to external blockchains via JSON-RPC, and
uses [tofnd](https://github.com/axelarnetwork/tofnd) for signing transactions and batches of messages.

### How to run

#### Configuration

Below is the config file format, with explanations for each entry:

```yaml
tm_jsonrpc=[JSON-RPC URL of Axelar node]
tm_grpc=[gRPC URL of Axelar node]
event_buffer_cap=[max blockchain events to queue. Will error if set too low]

[service_registry]
cosmwasm_contract=[address of service registry]

[broadcast]
batch_gas_limit=[max gas for a transaction. Transactions can contain multiple votes and signatures]
broadcast_interval=[how often to broadcast transactions]
chain_id=[chain id of Axelar network to connect to]
gas_adjustment=[gas adjustment to use when broadcasting]
gas_price=[gas price with denom, i.e. "0.007uaxl"]
queue_cap=[max messages to queue when broadcasting]
tx_fetch_interval=[how often to query for transaction inclusion in a block]
tx_fetch_max_retries=[how many times to query for transaction inclusion in a block before failing]
tx_confirmation_buffer_size=[maximum concurrent transaction confirmations (higher values improve throughput, lower values reduce resource usage; tune based on network and system capacity)]
tx_confirmation_queue_cap=[maximum size of the confirmation queue (larger values buffer more transactions during spikes but use more memory; smaller values risk dropping requests under load)]


[tofnd_config]
key_uid=[uid of key used for signing transactions]
party_uid=[metadata, should just be set to ampd]
url=[url of tofnd]

[grpc]
concurrency_limit_per_connection=[maximum number of concurrent requests the server can handle per client connection]
global_concurrency_limit=[maximum number of concurrent requests the server can handle globally across all connections]
ip_addr=[IP address on which the gRPC server will listen]
port=[port number on which the gRPC server will listen]
request_timeout=[maximum time allowed for processing a single request before timing out]

# One per supported chain
[[grpc.blockchain_service.chains]]
chain_name=[chain name]
multisig=[address of the multisig contract]
multisig_prover=[address of the multisig prover contract]
voting_verifier=[address of the voting verifier contract]

[monitoring_server]
enabled=[whether to enable the monitoring server]
bind_address=[the /status and /metrics endpoints bind address i.e. "127.0.0.1:3000"]
```

Below is an example config for connecting to a local axelard node and local tofnd process, and verifying transactions
from Flow testnet, Sui testnet and Stellar testnet.

```yaml
tm_jsonrpc="http://localhost:26657"
tm_grpc="tcp://localhost:9090"

event_buffer_cap=10000

[service_registry]
cosmwasm_contract="axelar1hrpna9v7vs3stzyd4z3xf00676kf78zpe2u5ksvljswn2vnjp3ystlgl4x"

[broadcast]
batch_gas_limit="10000000"
broadcast_interval="1s"
chain_id="devnet-amplifier"
gas_adjustment="2"
gas_price="0.00005uamplifier"
queue_cap="1000"
tx_fetch_interval="600ms"
tx_fetch_max_retries="10"
tx_confirmation_buffer_size = 10
tx_confirmation_queue_cap = 1000

[tofnd_config]
key_uid="axelar"
party_uid="ampd"
url="http://127.0.0.1:50051"

[grpc]
concurrency_limit_per_connection="32"
global_concurrency_limit="1024"
ip_addr="127.0.0.1"
port="9090"
request_timeout="30s"

[[grpc.blockchain_service.chains]]
chain_name="flow"
multisig="axelar14a4ar5jh7ue4wg28jwsspf23r8k68j7g5d6d3fsttrhp42ajn4xq6zayy5"
multisig_prover="axelar1rsuejfntt4rs2y8dn4dd3acszs00zyg9wpnsc6fmhevcp6plu5qspzn7e0"
voting_verifier="axelar1kkqdsqvwq9a7p9fj0w89wpx2m2t0vrxl782aslhq0kdw2xxd2aesv3un04"

[[grpc.blockchain_service.chains]]
chain_name="sui"
multisig="axelar14a4ar5jh7ue4wg28jwsspf23r8k68j7g5d6d3fsttrhp42ajn4xq6zayy5"
multisig_prover="axelar1v8jrupu2rqpskwgtr69max0ajul92q8z5mdxd505m2hu3xc5jzcqm8zyc6"
voting_verifier="axelar1sykyha8kzf35kc5hplqk76kdufntjn6w45ntwlevwxp74dqr3rvsq7fazh"

[[grpc.blockchain_service.chains]]
chain_name="stellar-2025-q3"
multisig="axelar14a4ar5jh7ue4wg28jwsspf23r8k68j7g5d6d3fsttrhp42ajn4xq6zayy5"
multisig_prover="axelar1aux2l6er84m6gtayqdwqhz4rl0txqdlj3v7szr72j7etve3jmpks7x4euy"
voting_verifier="axelar18y8p7dxesmxttvdzp5sqjksqrnh9xg32gtfqnkkucvv9de38f69qfn6ph3"


[monitoring_server]
enabled = false
bind_address = '127.0.0.1:3000'
```

By default, ampd loads the config file from `~/.ampd/config.toml` when running any command.
This can be overridden by passing `--config [path]`.

### Prerequisite: tofnd

Ampd needs access to a running tofnd instance in order to onboard as a verifier
or run the daemon. See the [tofnd repository](https://github.com/axelarnetwork/tofnd) for more info.

### Verifier Onboarding

Prior to running the ampd daemon, verifiers need to perform the following onboarding steps.

1. Determine your verifier address: `ampd verifier-address`

2. Fund your verifier address. This can be achieved in a number of ways and is dependent on the environment (mainnet,
   testnet or devnet).

3. Bond your verifier: `ampd bond-verifier [service name] [amount] [denom]`

4. Register your public key: `ampd register-public-key`

5. Authorize your verifier. This is dependent on the environment, and can be done via governance, or by the network
   operators.

6. Register support for desired chains. This enables ampd to participate in voting and signing for the specified chains.
   Multiple chain names can be passed, separated by a space.
   `ampd register-chain-support [service name] [chains]...`

### Run the daemon

`ampd`

A state file will be created if it doesn't yet exist. The default location of the state file is `~/.ampd/state.json`,
which can be overridden by passing `--state [path]`.

### Help

For more info about the available commands and options, run `ampd --help`.
