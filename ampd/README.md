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

[tofnd_config]
key_uid=[uid of key used for signing transactions]
party_uid=[metadata, should just be set to ampd]
url=[url of tofnd]

# multisig handler. This handler is used for all supported chains.
[[handlers]]
cosmwasm_contract=[address of multisig contract]
type="MultisigSigner"

# message verifier handler. One per supported chain
[[handlers]]
chain_name=[chain name. Not necessary in the Sui case]
chain_rpc_url=[URL of JSON-RPC endpoint for external chain]
cosmwasm_contract=[verifier contract address]
type=[handler type. Could be EvmMsgVerifier | SuiMsgVerifier  | StarknetMsgVerifier | SolanaMsgVerifier]

# handler to verify verifier set rotations. One per supported chain
[[handlers]]
chain_name=[chain name. Not necessary in the Sui case]
chain_rpc_url=[URL of JSON-RPC endpoint for external chain]
cosmwasm_contract=[verifier contract address]
type=[handler type. Could be EvmVerifierSetVerifier | SuiVerifierSetVerifier | StarknetVerifierSetVerifier | SolanaVerifierSetVerifier]

[monitoring_server]
enabled=[whether to enable the monitoring server]
bind_address=[the /status and /metrics endpoints bind address i.e. "127.0.0.1:3000"]
```

Below is an example config for connecting to a local axelard node and local tofnd process, and verifying transactions
from Avalanche testnet and Sui testnet.

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

[tofnd_config]
key_uid="axelar"
party_uid="ampd"
url="http://127.0.0.1:50051"

[[handlers]]
type = 'MultisigSigner'
cosmwasm_contract = 'axelar1au3qdftlypz3uydz9260aj4w73r7jm747zm5fsgrdnrlpwy7rrwqjzlemm'

[[handlers]]
type = 'SuiMsgVerifier'
cosmwasm_contract = 'axelar1hmdc9verjjfttcsav57nhcjm7hfcrpg08tqk9phcceulzurnfqns9yqsap'
rpc_url = "https://fullnode.testnet.sui.io:443"

[[handlers]]
type = 'SuiVerifierSetVerifier'
cosmwasm_contract = 'axelar1hmdc9verjjfttcsav57nhcjm7hfcrpg08tqk9phcceulzurnfqns9yqsap'
rpc_url = "https://fullnode.testnet.sui.io:443"

[[handlers]]
type = 'EvmMsgVerifier'
cosmwasm_contract = 'axelar14lh98gp06zdqh5r9qj3874hdmfzs4sh5tkfzg3cyty4xeqsufdjqedt3q8'
chain_name = 'avalanche'
chain_rpc_url = "https://api.avax-test.network/ext/bc/C/rpc"

[[handlers]]
type = 'StarknetMsgVerifier'
cosmwasm_contract = 'axelar1f7qqgp0zk8489s69xxszut07kxse7y5j6j5tune36x75dc9ftfsssdkf2u'
chain = 'starknet-devnet-v1'
rpc_url = "https://starknet-sepolia.public.blastapi.io/rpc/v0_7"

[[handlers]]
type = 'EvmVerifierSetVerifier'
cosmwasm_contract = 'axelar14lh98gp06zdqh5r9qj3874hdmfzs4sh5tkfzg3cyty4xeqsufdjqedt3q8'
chain_name = 'avalanche'
chain_rpc_url = "https://api.avax-test.network/ext/bc/C/rpc"

[[handlers]]
type = "SolanaMsgVerifier"
cosmwasm_contract = "axelar1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqecnww6"
chain_name = "solana"
chain_rpc_url = "https://api.devnet.solana.com"

[[handlers]]
cosmwasm_contract = "axelar1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqecnww6"
type = "SolanaVerifierSetVerifier"
chain_name = "solana"
chain_rpc_url = "https://api.devnet.solana.com"

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
