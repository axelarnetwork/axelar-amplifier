#!/usr/bin/env node

/*
Simple CLI to call VerifyEvents or query EventsStatus on the event-verifier contract.

Requirements:
  - Node 18+
  - From this folder:
      npm init -y
      npm i @cosmjs/cosmwasm-stargate @cosmjs/proto-signing @cosmjs/stargate js-sha3

Execute:
  node verify_events.js \
    --contract axelar1... \
    --cosmos-rpc https://rpc.axelar.devnet... \
    --mnemonic "... seed phrase ..." \
    --bech32-prefix axelar \
    --evm-rpc https://ethereum-sepolia-rpc/ \
    --chain-name Ethereum \
    --tx 0xabc... \
    --indexes 0,2 \
    [--gas-price 0.025uamplifier] \
    [--fee auto|<number>|'{"gas":"200000","amount":[{"denom":"uamplifier","amount":"5000"}]}' ]

Query only:
  node verify_events.js \
    --contract axelar1... \
    --cosmos-rpc https://rpc.axelar.devnet... \
    --evm-rpc https://ethereum-sepolia-rpc/ \
    --chain-name Ethereum \
    --tx 0xabc... \
    --indexes 0,2 \
    --query
*/

const { parseArgs } = require("node:util");
const { SigningCosmWasmClient } = require("@cosmjs/cosmwasm-stargate");
const { GasPrice } = require("@cosmjs/stargate");
const { DirectSecp256k1HdWallet, DirectSecp256k1Wallet } = require("@cosmjs/proto-signing");
const { keccak_256 } = require("js-sha3");

async function jsonRpc(url, method, params) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params })
  });
  if (!res.ok) throw new Error(`EVM RPC HTTP ${res.status}`);
  const json = await res.json();
  if (json.error) throw new Error(`EVM RPC error: ${JSON.stringify(json.error)}`);
  return json.result;
}

function parseIndexes(arg) {
  if (!arg) return [];
  return String(arg)
    .split(/[,\s]+/)
    .filter(Boolean)
    .map((x) => {
      const n = Number(x);
      if (!Number.isInteger(n) || n < 0) throw new Error(`invalid event index: ${x}`);
      return n;
    });
}

function hexToDecString(hex) {
  if (!hex) return "0";
  const clean = hex.startsWith("0x") ? hex : `0x${hex}`;
  return BigInt(clean).toString(10);
}

function strip0x(s) {
  if (s == null) return null;
  return s.startsWith("0x") ? s.slice(2) : s;
}

function hexToBase64(hex) {
  const clean = strip0x(hex) || "";
  if (clean.length === 0) return "";
  return Buffer.from(clean, "hex").toString("base64");
}

function toChecksumAddress(address) {
  const addr = (address || "").toLowerCase();
  const hex = strip0x(addr);
  if (!hex || hex.length !== 40) return address; // leave as-is if not a 20-byte hex
  const hash = keccak_256(hex);
  let ret = "0x";
  for (let i = 0; i < 40; i++) {
    const ch = hex[i];
    const hashNibble = parseInt(hash[i], 16);
    ret += /[a-f]/.test(ch) ? (hashNibble >= 8 ? ch.toUpperCase() : ch) : ch;
  }
  return ret;
}

function parseFeeArg(arg) {
  if (!arg || String(arg).toLowerCase() === "auto") return "auto";
  const s = String(arg).trim();
  if (s.startsWith("{") || s.startsWith("[")) {
    try {
      return JSON.parse(s);
    } catch (e) {
      throw new Error(`invalid --fee JSON: ${e.message}`);
    }
  }
  const n = Number(s);
  if (Number.isFinite(n) && n > 0) return n; // gas limit
  throw new Error(
    "--fee must be 'auto', a positive number (gas), or a JSON StdFee"
  );
}

// HexBinary in CosmWasm expects hex string encoding (no 0x prefix)

async function buildEventData(evmRpc, txHash, indexes, includeTxDetails) {
  const [tx, receipt] = await Promise.all([
    jsonRpc(evmRpc, "eth_getTransactionByHash", [txHash]),
    jsonRpc(evmRpc, "eth_getTransactionReceipt", [txHash])
  ]);

  if (!tx) throw new Error(`transaction not found: ${txHash}`);
  if (!receipt) throw new Error(`receipt not found: ${txHash}`);

  const logs = receipt.logs || [];
  const events = indexes.map((i) => {
    if (i < 0 || i >= logs.length) throw new Error(`event index out of bounds: ${i}`);
    const log = logs[i];
    return {
      contract_address: toChecksumAddress(log.address),
      event_index: i,
      topics: (log.topics || []).map((t) => strip0x(t)),
      data: log.data && log.data !== "0x" ? strip0x(log.data) : ""
    };
  });

  let transaction_details = null;
  if (includeTxDetails) {
    const valueDec = hexToDecString(tx.value);
    // The contract expects a non-zero Uint256; if zero, omit transaction_details
    if (valueDec !== "0") {
      transaction_details = {
        calldata: tx.input && tx.input !== "0x" ? strip0x(tx.input) : "",
        from: toChecksumAddress(tx.from),
        to: toChecksumAddress(tx.to ?? (receipt.contractAddress || "0x0000000000000000000000000000000000000000")),
        value: valueDec
      };
    }
  }

  return { evm: { transaction_details, events } };
}

async function getSignerFromArgs(args) {
  const prefix = args["bech32-prefix"] || args.prefix || "axelar";
  if (args.mnemonic) {
    const wallet = await DirectSecp256k1HdWallet.fromMnemonic(args.mnemonic, { prefix });
    const [account] = await wallet.getAccounts();
    return { wallet, sender: account.address };
  }
  if (args["private-key"]) {
    const hex = String(args["private-key"]).replace(/^0x/, "");
    const bytes = Uint8Array.from(Buffer.from(hex, "hex"));
    const wallet = await DirectSecp256k1Wallet.fromKey(bytes, prefix);
    const [account] = await wallet.getAccounts();
    return { wallet, sender: account.address };
  }
  throw new Error("provide --mnemonic or --private-key");
}

async function main() {
  const { values: args } = parseArgs({
    args: process.argv.slice(2),
    options: {
      contract: { type: "string" },
      "cosmos-rpc": { type: "string" },
      "evm-rpc": { type: "string" },
      "chain-name": { type: "string" },
      tx: { type: "string" },
      indexes: { type: "string" },
      mnemonic: { type: "string" },
      "private-key": { type: "string" },
      "bech32-prefix": { type: "string" },
      "gas-price": { type: "string" },
      fee: { type: "string" },
      query: { type: "boolean" },
      mode: { type: "string" },
      "include-tx-details": { type: "boolean" },
      "dry-run": { type: "boolean" }
    },
    allowPositionals: false
  });

  const isQuery = Boolean(args["query"]) || String(args["mode"] || "").toLowerCase() === "query";
  const required = ["contract", "cosmos-rpc", "evm-rpc", "chain-name", "tx", "indexes"];
  for (const k of required) {
    if (!args[k]) throw new Error(`missing --${k}`);
  }

  const includeTxDetails = args["include-tx-details"] === true || String(args["include-tx-details"]).toLowerCase() === "true";
  const indexes = parseIndexes(args.indexes);
  if (indexes.length === 0) throw new Error("--indexes must contain at least one index");

  const event_data = await buildEventData(args["evm-rpc"], args.tx, indexes, includeTxDetails);

  const event = {
    event_id: {
      source_chain: String(args["chain-name"]),
      transaction_hash: String(args.tx)
    },
    event_data
  };

  const queryMsg = { events_status: [event] };
  const execMsg = { verify_events: [event] };

  if (args["dry-run"]) {
    console.log(JSON.stringify(isQuery ? queryMsg : execMsg, null, 2));
    return;
  }

  if (isQuery) {
    const { CosmWasmClient } = require("@cosmjs/cosmwasm-stargate");
    const q = await CosmWasmClient.connect(args["cosmos-rpc"]);
    const res = await q.queryContractSmart(String(args.contract), queryMsg);
    console.log(JSON.stringify(res, null, 2));
    return;
  }

  const { wallet, sender } = await getSignerFromArgs(args);
  const gasPriceStr = args["gas-price"] || "0.025uaxl";
  const client = await SigningCosmWasmClient.connectWithSigner(
    args["cosmos-rpc"],
    wallet,
    { gasPrice: GasPrice.fromString(gasPriceStr) }
  );

  const fee = parseFeeArg(args.fee);
  const result = await client.execute(sender, String(args.contract), execMsg, fee);
  console.log(JSON.stringify({ txHash: result.transactionHash }, null, 2));
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});


