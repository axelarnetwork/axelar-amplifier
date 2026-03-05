# Ampd

Ampd is the off-chain daemon responsible for voting and signing within the amplifier protocol.
The daemon listens to the Axelar blockchain for specific events and
uses [tofnd](https://github.com/axelarnetwork/tofnd) for signing transactions and batches of messages.

Ampd exposes a gRPC server that **handler** processes connect to. Handlers are separate binaries that
handle chain-specific verification and signing logic (e.g. verifying EVM transactions, Solana messages, etc.).

## Architecture

```
                    ┌───────────────────────────────────┐
                    │          Axelar Node              │
                    │  (JSON-RPC :26657, gRPC :9090)    │
                    └──────────────┬────────────────────┘
                                   │
                    ┌──────────────▼─────────────────────┐
┌────────┐          │            ampd                    │
│ tofnd  │◄─────────│  - subscribes to chain events      │
│ :50051 │          │  - broadcasts transactions         │
└────────┘          │  - gRPC server for handlers :9090  │
                    └───────────────┬────────────────────┘
                                    │ gRPC
              ┌────────────┬────────┼───────┬────────────┐
              │            │        │       │            │
          ┌───▼───┐   ┌────▼───┐ ┌──▼────┐ ┌──▼────┐ ┌───▼───┐
          │  evm  │   │ solana │ │  sui  │ │stellar│ │ xrpl  │
          │handler│   │handler │ |handler│ │handler│ │handler│
          └───────┘   └────────┘ └───────┘ └───────┘ └───────┘
              │            │         │         │          │
          EVM RPC       Solana   Sui RPC   Stellar   XRPL RPC
                          RPC                RPC
```

Running a verifier requires:
1. **tofnd** - threshold signing service
2. **ampd** - core daemon with gRPC server
3. **One handler per chain** you want to support

## Download

Prebuilt binaries for ampd and all handlers are available on the
[GitHub Releases page](https://github.com/axelarnetwork/axelar-amplifier/releases).

**ampd** releases are tagged as `ampd-v*` (e.g. `ampd-v1.14.2`) and include binaries for
linux-amd64, linux-arm64 and darwin-arm64.

**Handler** releases are tagged as `<handler>-v*` (e.g. `evm-handler-v0.1.1`, `solana-handler-v0.1.3`)
and include linux-amd64 binaries.

Alternatively, build from source:
```bash
# ampd
cargo build --release -p ampd

# all handlers
cargo build --release -p ampd-handlers
```

This produces `ampd`, `evm-handler`, `solana-handler`, `sui-handler`, `stellar-handler`
and `xrpl-handler` in `target/release/`.

### Docker images

Prebuilt Docker images are available on Docker Hub:

```bash
# ampd
docker pull axelarnet/axelar-ampd:<version>          # e.g. v1.14.2

# handlers (one image per handler type)
docker pull axelarnet/axelar-ampd-evm-handler:<version>
docker pull axelarnet/axelar-ampd-solana-handler:<version>
docker pull axelarnet/axelar-ampd-sui-handler:<version>
docker pull axelarnet/axelar-ampd-stellar-handler:<version>
docker pull axelarnet/axelar-ampd-xrpl-handler:<version>
```

To build images locally:

```bash
# ampd
docker build -f ampd/Dockerfile -t ampd .

# handlers (pass HANDLER build arg)
docker build -f ampd-handlers/Dockerfile --build-arg HANDLER=evm -t evm-handler .
docker build -f ampd-handlers/Dockerfile --build-arg HANDLER=solana -t solana-handler .
# etc.
```

See [Running via Docker](#running-via-docker) below for how to run the containers
(requires tofnd and configuration first).

## How to run

### Prerequisite: tofnd

Ampd needs access to a running tofnd instance in order to onboard as a verifier
or run the daemon. See the [tofnd repository](https://github.com/axelarnetwork/tofnd) for more info.

### Ampd Configuration

Below is the full config file format with explanations for each entry:

```toml
# Tendermint JSON-RPC endpoint of the Axelar node
tm_jsonrpc = "http://localhost:26657"

# Tendermint gRPC endpoint of the Axelar node
tm_grpc = "tcp://localhost:9090"

# Timeout for Tendermint gRPC calls (default: 5s)
tm_grpc_timeout = "5s"

[broadcast]
chain_id = "axelar-dojo-1"                 # chain id of the Axelar network
tx_fetch_interval = "500ms"                # how often to poll for tx confirmation
tx_fetch_max_retries = 10                  # max retries for tx confirmation
gas_adjustment = 1.2                       # gas multiplier for safety margin
gas_price = "0.00005uaxl"                  # gas price with denom
batch_gas_limit = 1000000                  # max gas per transaction batch
queue_cap = 1000                           # max messages to queue
broadcast_interval = "1s"                  # min interval between broadcasts
tx_confirmation_buffer_size = 10           # concurrent tx confirmations
tx_confirmation_queue_cap = 1000           # confirmation queue size

[tofnd_config]
url = "http://localhost:50051"             # tofnd service URL
party_uid = "ampd"                         # metadata identifier
key_uid = "axelar"                         # key identifier for signing
timeout = "3s"                             # request timeout

[service_registry]
cosmwasm_contract = "axelar1..."           # service registry contract address

[rewards]
cosmwasm_contract = "axelar1..."           # rewards contract address

# gRPC server that handlers connect to
[grpc]
ip_addr = "127.0.0.1"                      # listen address
port = 9090                                # listen port
global_concurrency_limit = 1024            # max concurrent requests globally
concurrency_limit_per_connection = 32      # max concurrent requests per connection
request_timeout = "30s"                    # per-request timeout

# One entry per supported chain (must match what handlers expect)
[[grpc.blockchain_service.chains]]
chain_name = "ethereum"
voting_verifier = "axelar1..."             # voting verifier contract
multisig_prover = "axelar1..."             # multisig prover contract
multisig = "axelar1..."                    # multisig contract

[monitoring_server]
enabled = false
bind_address = "127.0.0.1:3000"           # /status and /metrics endpoint
channel_size = 1000                        # metric buffer capacity

[event_sub]
block_processing_buffer = 10               # concurrent blocks to process
poll_interval = "1s"                       # how often to poll for new blocks
retry_delay = "3s"                         # delay before retrying failed fetches
retry_max_attempts = 3                     # max retry attempts
stream_buffer_size = 100000                # max events to buffer
delay = "1s"                               # delay before processing blocks

[tm_client]
max_retries = 15                           # max retries for Tendermint RPC calls
retry_delay = "1s"                         # delay between retries
```

Below is an example config for connecting to a local axelard node and local tofnd process,
supporting Flow testnet, Sui testnet and Stellar testnet.

```toml
tm_jsonrpc = "http://localhost:26657"
tm_grpc = "tcp://localhost:9090"

[service_registry]
cosmwasm_contract = "axelar1hrpna9v7vs3stzyd4z3xf00676kf78zpe2u5ksvljswn2vnjp3ystlgl4x"

[broadcast]
chain_id = "devnet-amplifier"
tx_fetch_interval = "600ms"
tx_fetch_max_retries = 10
gas_adjustment = 2.0
gas_price = "0.00005uamplifier"
batch_gas_limit = 10000000
queue_cap = 1000
broadcast_interval = "1s"
tx_confirmation_buffer_size = 10
tx_confirmation_queue_cap = 1000

[tofnd_config]
url = "http://127.0.0.1:50051"
party_uid = "ampd"
key_uid = "axelar"
timeout = "3s"

[grpc]
ip_addr = "127.0.0.1"
port = 9090
global_concurrency_limit = 1024
concurrency_limit_per_connection = 32
request_timeout = "30s"

[[grpc.blockchain_service.chains]]
chain_name = "flow"
multisig = "axelar14a4ar5jh7ue4wg28jwsspf23r8k68j7g5d6d3fsttrhp42ajn4xq6zayy5"
multisig_prover = "axelar1rsuejfntt4rs2y8dn4dd3acszs00zyg9wpnsc6fmhevcp6plu5qspzn7e0"
voting_verifier = "axelar1kkqdsqvwq9a7p9fj0w89wpx2m2t0vrxl782aslhq0kdw2xxd2aesv3un04"

[[grpc.blockchain_service.chains]]
chain_name = "sui"
multisig = "axelar14a4ar5jh7ue4wg28jwsspf23r8k68j7g5d6d3fsttrhp42ajn4xq6zayy5"
multisig_prover = "axelar1v8jrupu2rqpskwgtr69max0ajul92q8z5mdxd505m2hu3xc5jzcqm8zyc6"
voting_verifier = "axelar1sykyha8kzf35kc5hplqk76kdufntjn6w45ntwlevwxp74dqr3rvsq7fazh"

[[grpc.blockchain_service.chains]]
chain_name = "stellar-2025-q3"
multisig = "axelar14a4ar5jh7ue4wg28jwsspf23r8k68j7g5d6d3fsttrhp42ajn4xq6zayy5"
multisig_prover = "axelar1aux2l6er84m6gtayqdwqhz4rl0txqdlj3v7szr72j7etve3jmpks7x4euy"
voting_verifier = "axelar18y8p7dxesmxttvdzp5sqjksqrnh9xg32gtfqnkkucvv9de38f69qfn6ph3"

[monitoring_server]
enabled = false
bind_address = "127.0.0.1:3000"
```

By default, ampd loads the config file from `~/.ampd/config.toml` when running any command.
This can be overridden by passing `--config [path]`. Config values can also be set via
environment variables with the `AMPD_` prefix (e.g. `AMPD_TM_JSONRPC`, `AMPD_BROADCAST__CHAIN_ID`).

**Note on required fields:** Sections that are completely omitted get sensible defaults. However, if you
include a section (e.g. `[broadcast]`), all fields within it are required. See the full config reference
above or `ampd/src/tests/config_template.toml` for a complete example with all fields.

### Handler Configuration

Handlers are separate binaries that connect to ampd's gRPC server. Available handlers:

| Binary | Chains | Image |
|--------|--------|-------|
| `evm-handler` | Ethereum, Flow, Hedera, Berachain, etc. | `axelarnet/axelar-ampd-evm-handler` |
| `solana-handler` | Solana | `axelarnet/axelar-ampd-solana-handler` |
| `sui-handler` | Sui | `axelarnet/axelar-ampd-sui-handler` |
| `stellar-handler` | Stellar | `axelarnet/axelar-ampd-stellar-handler` |
| `xrpl-handler` | XRPL | `axelarnet/axelar-ampd-xrpl-handler` |

Each handler is started with:

```bash
<handler-binary> --config-dir <path>
```

The config directory must contain a **base config** (`config.toml`) and a **handler-specific config** file.

#### Base handler config (`config.toml`)

Common to all handlers:

```toml
# URL of ampd's gRPC server (default: http://127.0.0.1:9090)
ampd_url = "http://127.0.0.1:9090"

# Chain name (must match a chain in ampd's grpc.blockchain_service.chains)
chain_name = "ethereum"

# Event handler tuning (optional, these are the defaults)
stream_timeout = "10s"
retry_delay = "1s"
retry_max_attempts = 3
```

Can also be set via `AMPD_HANDLERS_` env vars (e.g. `AMPD_HANDLERS_CHAIN_NAME=ethereum`).

#### Handler-specific configs

**EVM** (`evm-handler-config.toml`, env prefix: `AMPD_EVM_HANDLER`):
```toml
rpc_url = "https://testnet.evm.nodes.onflow.org"
rpc_timeout = "3s"                          # default: 3s
finalization = "RPCFinalizedBlock"          # or "ConfirmationHeight"
# confirmation_height = 20                  # required if finalization = "ConfirmationHeight"
gmp_handler_enabled = true                  # default: true
event_verifier_handler_enabled = false      # default: false
```

**Solana** (`solana-handler-config.toml`, env prefix: `AMPD_SOLANA_HANDLER`):
```toml
rpc_url = "https://api.devnet.solana.com"
rpc_timeout = "3s"                          # default: 3s
gateway_address = "gtwT4uGVTYSPnTGv6rSpMheyFyczUicxVWKqdtxNGw9"   # base58 pubkey
domain_separator = "618644b4dfbd1e1277cbd472750a1c49ce46c9234207cd42609f79e9309cecbb"  # hex, 32 bytes
```

**Sui** (`sui-handler-config.toml`, env prefix: `AMPD_SUI_HANDLER`):
```toml
rpc_url = "https://fullnode.testnet.sui.io"
rpc_timeout = "3s"                          # default: 3s
```

**Stellar** (`stellar-handler-config.toml`, env prefix: `AMPD_STELLAR_HANDLER`):
```toml
rpc_url = "https://soroban-testnet.stellar.org"
```

**XRPL** (`xrpl-handler-config.toml`, env prefix: `AMPD_XRPL_HANDLER`):
```toml
rpc_url = "https://s.altnet.rippletest.net:51234"
rpc_timeout = "3s"                          # default: 3s
```

Environment variables override file values for each handler
(e.g. `AMPD_SOLANA_HANDLER_RPC_URL=https://...`).

#### Example: single-machine setup for Flow and Sui

Directory layout:
```
~/.ampd/
  config.toml              # ampd config (see above)
  state.json               # ampd state (auto-created)

~/flow-handler/
  config.toml              # base: ampd_url, chain_name = "flow"
  evm-handler-config.toml  # evm-specific: rpc_url, finalization

~/sui-handler/
  config.toml              # base: ampd_url, chain_name = "sui"
  sui-handler-config.toml  # sui-specific: rpc_url
```

Start all processes:
```bash
# 1. Start tofnd
tofnd

# 2. Start ampd
ampd

# 3. Start handlers (one per chain)
evm-handler --config-dir ~/flow-handler/
sui-handler --config-dir ~/sui-handler/
```

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

### Running via Docker

Ensure tofnd is running and reachable, and your ampd config is ready (see above).

```bash
# ampd (mount config and state dir, expose gRPC port for handlers)
docker run -p 9090:9090 \
  -v ~/.ampd:/home/axelard/.ampd \
  axelarnet/axelar-ampd:<version>

# handlers (configure via env vars, no config files needed)
docker run \
  -e AMPD_HANDLERS_AMPD_URL=http://<ampd-host>:9090 \
  -e AMPD_HANDLERS_CHAIN_NAME=flow \
  -e AMPD_EVM_HANDLER_RPC_URL=https://testnet.evm.nodes.onflow.org \
  -e AMPD_EVM_HANDLER_FINALIZATION=RPCFinalizedBlock \
  axelarnet/axelar-ampd-evm-handler:<version>
```

Networking requirements:
- **ampd** must be able to reach tofnd (default `:50051`) and the Axelar node (JSON-RPC `:26657`, gRPC `:9090`)
- **handlers** must be able to reach ampd's gRPC (default `:9090`) and external chain RPCs (outbound internet)
- If running all containers on the same machine, use a shared Docker network or `--network host` so they can communicate

### Help

For more info about the available commands and options, run `ampd --help`.
