# Glossary

This page defines the XRPL and Axelar specific terms used in the rest of the book. 

## XRPL terms

### account_tx

The XRPL JSON RPC method that returns a paginated list of transactions involving a given account. The XRPL relayer polls `account_tx` for the multisig account to discover new user payments and to detect inclusion of multisig prover outputs.

### Canonical serialization
The deterministic XRPL byte format used when hashing a transaction for signing. Every field is sorted by its protocol defined `type_code` and `field_code` and encoded in a fixed wire format. Because XRPL nodes all agree on this serialization, any signer can independently produce the same bytes from the same transaction structure and arrive at the same digest. Multi signing makes this rule sensitive: each signer must append their own account address to the canonical bytes before hashing.

### Classic address
The base58 encoded XRPL account identifier, starting with `r` (for example, `rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY`). It is the human readable form of a 20 byte account id derived from `RIPEMD160(SHA256(public_key))`.

### Currency code
A 3 character ASCII code (such as `USD`) or a 40 character (20 byte) hex code identifying an IOU. The first form is reserved for common ASCII codes; the second form is required for any code that is not exactly 3 ASCII letters. The pair `(currency, issuer)` uniquely identifies an IOU on XRPL.

### DisableMaster (Master Key)
Every XRPL account is created with a master key derived from its account seed. `DisableMaster` is an `AccountSet` flag that turns off the master key, leaving the account controllable only through the `SignerList`. The multisig account that acts as the bridge gateway has `DisableMaster` set, so no single party can move funds out of it.

### Drop
The smallest unit of native XRP. One XRP equals 10<sup>6</sup> drops. All XRP amounts in XRPL transactions are denominated in drops as a u64 integer. XRP itself has 6 decimals from the bridge's point of view.

### IOU (issued currency)
XRPL's primitive for any token that is not XRP. An IOU is identified by the pair `(currency_code, issuer_account)` and is created implicitly when its issuer makes a `Payment` of that currency to an account that has opened a trust line. The bridge uses IOUs to represent tokens that originate on other chains: the multisig account is the issuer and mints the IOU to the recipient.

### Memos
A transaction field on XRPL that carries arbitrary byte data. Each memo entry holds three optional sub fields: `MemoType`, `MemoData`, and `MemoFormat`, each encoded as hex. The bridge uses memos as a structured key value store. The exact set of expected keys depends on the value of the `type` memo: an `interchain_transfer` or `call_contract` payment encodes `destination_chain`, `destination_address`, `gas_fee_amount`, and an optional `payload`; an `add_gas` payment encodes only `msg_id`; an `add_reserves` payment carries no further keys.

### Multisig account
A regular XRPL account that has had a `SignerListSet` transaction applied to define a list of signers, each with a weight, plus a quorum threshold. Once configured this way (and with the master key disabled), the account can only send transactions that have been signed by enough listed signers to reach the quorum. The bridge gateway is exactly such an account; the signer list mirrors the active Axelar verifier set.

### Payment
The XRPL transaction type used to move value, either native XRP between accounts or an IOU between accounts that share a trust line. The bridge uses `Payment` both inbound (the user paying the multisig account) and outbound (the multisig account paying the recipient).

### Reserve
A minimum XRP balance every XRPL account must keep in order to exist. There is a fixed **base reserve** per account, plus an **owner reserve** per owned object (each ticket, each trust line, each signer list entry, and so on). The multisig account's reserve is the dominant variable cost of running the bridge over time; it grows with the number of trust lines the gateway opens to receive local origin IOUs.

### Sequence number
A per account counter that increments with every transaction the account sends. Comparable to an EVM nonce. Native XRPL transactions must use strictly increasing sequence numbers, which serializes activity for a given account. Tickets exist to relax this for parallel work.

### SHA 512 half
The XRPL hashing primitive: compute SHA 512 over the input and take the first 256 bits. Used for all transaction and signing hashes. Multi signing prepends the 4 byte `SMT\0` prefix and appends the signer's account id before hashing.

### SignerList / SignerListSet
The XRPL transaction type that configures or updates an account's multi signing rules. The transaction lists signers (by public key or account id) with weights, and sets a quorum threshold. The bridge uses `SignerListSet` to rotate the gateway's signer list to the next Axelar verifier set when the set changes.

### Ticket
An XRPL primitive that reserves a sequence number for later use. The multisig account periodically issues `TicketCreate` transactions to pre allocate a batch of up to 250 tickets. Each subsequent outbound payment consumes one ticket from the pool, which allows multiple in flight bridge transactions to be confirmed out of order without sequence collisions. Tickets are owned objects and count against the account reserve while held.

### tfPartialPayment
A `Payment` transaction flag that, when set, allows the delivered amount to be less than the `Amount` field (XRPL uses this for path finding through illiquid trust lines). The bridge defends against it: the off chain verifiers reject any inbound payment whose `delivered_amount` is not equal to `Amount`, and they also reject payments with any flag set. Without this defense an attacker could spend a tiny amount on XRPL and have a much larger transfer credited on the destination chain.

### Trust line
The on chain relationship between two XRPL accounts allowing one (the holder) to hold an IOU issued by the other (the issuer). Trust lines are XRPL's mechanism for opt-in token holding: an account never automatically receives an IOU unless it has previously opened a trust line to the issuer with a non-zero limit. The trust line records the holder, the issuer, the currency code, and the maximum amount the holder is willing to hold. It is created and updated by the [TrustSet](#trustset) transaction.

Two trust line scenarios apply to the bridge:
* **For IOUs that originate on XRPL**: the multisig account needs a trust line against the issuer so it can hold and later send the IOU back out on outbound transfers.
* **For IOUs that represent assets from another chain**: the recipient on XRPL needs a trust line against the multisig account (which is the issuer of these remote-origin IOUs) before they can receive the IOU. Without it the XRPL ledger rejects the inbound `Payment`.

### TrustSet
The XRPL transaction type that creates or modifies a [trust line](#trust-line). Submitted by the *holder* side of the relationship, citing the issuer account, the currency code, and a numeric limit. Unique to XRPL: it does not exist in EVM, Solana, or other chain models the bridge connects to. Each open trust line is an "owned object" on the holder's account and consumes an owner [reserve](#reserve) in XRP, which is why opening many local-IOU trust lines on the multisig account drives the dominant variable cost of running the bridge.

The bridge issues `TrustSet` transactions in one specific case: when an operator calls `TrustSet { token_id }` on the [XRPL Multisig Prover](../contracts/xrpl_multisig_prover.md) to allow the multisig account to hold a newly-registered XRPL-native IOU. End-user recipients open their own `TrustSet` transactions independently of the bridge (using a normal XRPL wallet) before they can receive remote-origin tokens.

### XRP
The native currency of the XRPL ledger. Denominated in drops at the protocol level. Used by the bridge both as a transferable asset and as the fee/reserve currency for the multisig account itself.

## Axelar Amplifier protocol terms

### ampd
The Amplifier off chain daemon that each verifier runs. It maintains the Tendermint RPC connection to the Axelar chain, subscribes to chain events, broadcasts Cosmos transactions, and exposes a local gRPC server for chain specific handler binaries to plug into. Documentation lives [upstream](https://github.com/axelarnetwork/axelar-amplifier/tree/main/ampd).

### Amplifier
Axelar's modular cross chain protocol. Anyone can permissionlessly connect a new chain by deploying a small set of CosmWasm contracts on Axelar and integrating with the protocol's verifier set. The XRPL integration is one such connection.

### Axelar GMP API
A hosted service that sits in front of the Axelar chain and exposes a single HTTP interface for external chain relayers. It abstracts away the internals of Axelar routing: relayers do not need to talk directly to the CosmWasm contracts, subscribe to Tendermint events, or build Cosmos transactions themselves. Instead they post broadcast requests to the API (targeting a contract address) and pull tasks from it for events emitted by the Axelar chain.

### Axelarnet Gateway
The CosmWasm contract on Axelar that lets Axelar resident contracts (such as the ITS Hub) send and receive cross chain messages. Documentation lives [upstream](https://github.com/axelarnetwork/axelar-amplifier/tree/main/contracts/axelarnet-gateway).

### Coordinator
The CosmWasm contract that owns deployment metadata for each connected chain's contract set and acts as the unbonding gate when a verifier wants to withdraw their stake. See [`coordinator`](../contracts/coordinator.md).

### Cross chain id (cc_id)
The identifier shared across chains for a single message. Consists of `(chain, id)`, where `chain` is the source chain name and `id` is the chain native message identifier (for XRPL, the transaction hash). The router and gateways use cc_id to track a message end to end.

### GMP (general message passing)
The capability for one chain to call a contract on another chain, optionally with attached calldata. Token transfers are a special case of GMP; pure GMP carries only calldata. The bridge supports pure GMP from XRPL (a `call_contract` payment) but not into XRPL (because XRPL has no executable destination).

### ITS (Interchain Token Service)
The Axelar protocol layer on top of GMP that handles cross chain tokens: deployment, linking, and transfers. Documentation lives upstream alongside the [ITS Hub](https://github.com/axelarnetwork/axelar-amplifier/tree/main/contracts/interchain-token-service) and the [Solidity ITS edge implementation](https://github.com/axelarnetwork/interchain-token-service).

### ITS edge
The per chain ITS contract that talks to the ITS Hub. On smart contract chains this is a dedicated contract (Solidity, Move, and so on). On XRPL the role is absorbed by [`xrpl-gateway`](../contracts/xrpl_gateway.md).

### ITS Hub
The CosmWasm contract on Axelar that routes ITS messages between edges. It validates the source, tracks per chain supply for every token id, rescales amounts for decimal differences between chains, and re wraps messages between the `SendToHub` and `ReceiveFromHub` envelopes. Documentation lives [upstream](https://github.com/axelarnetwork/axelar-amplifier/tree/main/contracts/interchain-token-service).

### Multisig contract
The generic CosmWasm contract on Axelar that coordinates signing sessions. The XRPL prover opens sessions on this contract; verifiers submit signature shares; once quorum is met, the contract exposes the assembled signatures for the relayer to fetch. See [`multisig`](../contracts/multisig.md).

### Poll
A verification session opened by a voting verifier contract. A weighted snapshot of the active verifier set is taken from the service registry at the moment the poll is opened, and verifiers vote on the candidate messages. A poll ends when its block expiry is reached; results are stored on chain.

### Quorum
The weighted threshold required for a poll or signing session to reach consensus. Configured at the voting verifier level (for polls) and at the prover level (for signing sessions). For XRPL the prover's `signing_threshold` is mirrored into the XRPL `SignerListSet`, so that the on ledger multisig rules match the on chain Axelar rules for outbound transactions.

### Relayer
An off chain process that watches one chain for events and submits the corresponding messages to the next chain in the GMP path. Relayers are permissionless: anyone can run the same code. For XRPL, a dedicated Rust relayer handles XRPL specific quirks (ticket creation, fee reserves, etc.); its source is at [`axelarnetwork/axelar-relayer-xrpl`](https://github.com/axelarnetwork/axelar-relayer-xrpl).
### Router
The CosmWasm contract on Axelar that maintains the registry of connected chains and their gateways and routes verified messages from a source chain's gateway to a destination chain's gateway. See [`router`](../contracts/router.md).

### Service Registry
The CosmWasm contract that tracks verifier bonding, authorization, and per chain support. The voting verifier and the prover both query it for the active verifier set when opening polls or signing sessions. See [`service-registry`](../contracts/service_registry.md).

### Token id
A 32 byte identifier shared across all chains for a given linked token set. Token ids are derived deterministically from a deployer plus salt or canonical bytes, so the same id can be computed on any chain that knows the inputs. The ITS Hub indexes per chain token state by token id.

### Token manager
A per token, per chain construct that defines how tokens move on that chain. Common types are `MINT_BURN`, `MINT_BURN_FROM`, `LOCK_UNLOCK`, `LOCK_UNLOCK_FEE`, and `NATIVE_INTERCHAIN_TOKEN`. The XRPL side does not have explicit token manager contracts; the multisig account fills the role implicitly by issuing or burning IOUs and by holding or releasing native XRP.

### tofnd
The Axelar key management daemon that ampd talks to over gRPC. It holds verifier signing keys and produces signatures on request, supporting both **ECDSA (secp256k1)** and **Ed25519** (the algorithm is selected per request via the `Algorithm` field). The Cosmos transactions that ampd broadcasts to the Axelar chain are ECDSA-signed; the XRPL multi-sign shares are also ECDSA, but other chains that the verifier supports may use Ed25519 (for example, Solana). Documentation lives [upstream](https://github.com/axelarnetwork/tofnd).

### Verifier
An off chain operator that participates in the Amplifier protocol by bonding stake in the service registry, voting in polls, and signing in multisig sessions. Verifiers are not chain specific; the same verifier can support many chains by registering chain support for each.

### Voting Verifier
The CosmWasm contract that runs polls over messages reported from an external chain. There is one voting verifier per connected chain. For XRPL it is [`xrpl-voting-verifier`](../contracts/xrpl_voting_verifier.md), which has an XRPL specific poll variant.

## Bridge specific terms

### AddGas / AddGasMessage
An XRPL message variant used to top up the gas allocation of an in flight cross chain message that the user underfunded. The user sends an XRPL payment to the multisig account with memo `type=add_gas` and `msg_id=<original-message-id>`. After voting verifier confirmation the additional amount is credited to the gateway's accrued gas tally.

### AddReserves / AddReservesMessage
An XRPL message variant used by operators to top up the multisig account's XRP balance so it can keep paying transaction fees and meet its reserve requirements. The operator sends XRP to the multisig account with memo `type=add_reserves`. After confirmation the prover's tracked fee reserve increases.

### CallContractMessage
An XRPL message variant used for pure general message passing from XRPL. The XRPL `Payment` carries no transferable value beyond the gas fee, but it carries a `payload` memo whose contents are delivered to the destination contract. There is no inbound counterpart; XRPL cannot host an executable destination.

### InterchainTransferMessage
An XRPL message variant used for cross chain token transfers originating on XRPL. The `Payment` carries the transfer amount plus the gas fee, and optional payload.

### ProverMessage
An XRPL specific `XRPLMessage` (the enum defined in upstream [`packages/xrpl-types`](https://github.com/axelarnetwork/axelar-amplifier/blob/main/packages/xrpl-types/src/msg.rs)) variant. After the multisig account submits a prover-built XRPL transaction (a Payment, SignerListSet, TicketCreate, or TrustSet) to the ledger, the relayer reports the inclusion (or failure) of that transaction back to Axelar as a `ProverMessage`. The [xrpl-voting-verifier](../contracts/xrpl_voting_verifier.md) opens a poll on it, verifiers look up the XRPL transaction over JSON RPC and vote, and once quorum is reached the relayer calls `ConfirmProverMessage` on the [xrpl-multisig-prover](../contracts/xrpl_multisig_prover.md). That call releases the [ticket](#ticket), clears the stored payload, and (for `SignerListSet`) promotes the new verifier set. This is the only mechanism by which the Axelar side learns that an outbound XRPL transaction landed, because XRPL has no contract that could emit an event for it.

### Wrapped XRP (wXRP)
The on chain representation of native XRP on chains other than XRPL. On XRPL EVM in particular, wXRP is an ERC-20 contract minted by the local ITS edge when XRP arrives over the bridge and burned when XRP leaves to be redeemed for native XRP on XRPL. The bridge treats wXRP and native XRP as two representations of the same token id, with the ITS Hub tracking per chain supply.

### xrpl-gateway
The CosmWasm contract on Axelar that acts as the gateway and ITS edge for XRPL traffic. See [`xrpl-gateway`](../contracts/xrpl_gateway.md).

### xrpl-multisig-prover
The CosmWasm contract on Axelar that builds and tracks XRPL transactions submitted by the multisig account. See [`xrpl-multisig-prover`](../contracts/xrpl_multisig_prover.md).

### xrpl-voting-verifier
The CosmWasm contract on Axelar that runs polls over XRPL transactions, including outbound prover transactions reported back as `ProverMessage`. See [`xrpl-voting-verifier`](../contracts/xrpl_voting_verifier.md).
