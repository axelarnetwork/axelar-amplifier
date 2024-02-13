#!/bin/bash

# Setup instructions: https://bright-ambert-2bd.notion.site/Axelar-CosmWasm-Devnet-Development-885a966bf4764151a7e4c1fde68a04a2

# Assumes:
# (1) `axelard` is set up
# (2) an account called "test" has been generated via `axelard keys add test`
# (3) "test" acocunt (`axelard keys show -a test`) is funded

# bash +x e2e.sh

RPC_URL="http://devnet.rpc.axelar.dev:26657"

#docker run --rm -v "$(pwd)":/code \
#  --mount type=volume,source="$(basename "$(pwd)")_cache",target=/target \
#  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
#  cosmwasm/workspace-optimizer-arm64:0.14.0

axelard keys show -a test

RES=$(axelard tx wasm store artifacts/service_registry-aarch64.wasm --from test --gas-prices 0.1uwasm --gas auto --gas-adjustment 2 -y --output json -b block --node $RPC_URL)
CODE_ID=$(echo $RES | jq -r '.logs[0].events[-1].attributes[1].value')
axelard tx wasm instantiate $CODE_ID '{"governance_account":"axelar1lsasewgqj7698e9a25v3c9kkzweee9cvejq5cs"}' --from test --label "my first contract" --gas-prices 0.025uwasm --gas auto --gas-adjustment 2 -b block -y --no-admin --node $RPC_URL

SERVICE_REGISTRY=$(axelard query wasm list-contract-by-code $CODE_ID --output json --node $RPC_URL | jq -r '.contracts[0]')
echo $SERVICE_REGISTRY

RES=$(axelard tx wasm store artifacts/voting_verifier-aarch64.wasm --from test --gas-prices 0.1uwasm --gas auto --gas-adjustment 2 -y --output json -b block --node $RPC_URL)
CODE_ID=$(echo $RES | jq -r '.logs[0].events[-1].attributes[1].value')
SERVICE_NAME="ntomates"

axelard tx wasm instantiate $CODE_ID '{"service_name":'$SERVICE_NAME',"service_registry_address":"'$SERVICE_REGISTRY'","source_gateway_address":"axelar12zspmv779z9wf4cp2909m0zt6ga43z24stcy5dhc2twmzp4g6n2s7tahku","voting_threshold":["1","1"],"block_expiry":8439238928492389123,"confirmation_height":0,"source_chain":"a"}' --from test --label "my first contract" --gas-prices 0.025uwasm --gas auto --gas-adjustment 2 -b block -y --no-admin --node $RPC_URL

VOTING_VERIFIER=$(axelard query wasm list-contract-by-code $CODE_ID --output json --node $RPC_URL | jq -r '.contracts[0]')
echo $VOTING_VERIFIER

axelard tx wasm execute $SERVICE_REGISTRY '{"register_service":{"service_name":'$SERVICE_NAME',"service_contract":"$VOTING_VERIFIER","min_num_workers":1,"max_num_workers":2,"min_worker_bond":"0","bond_denom":"uwasm","unbonding_period_days":9,"description":"a"}}' --from test --gas-prices 0.025uwasm --gas auto --gas-adjustment 2 -y --node $RPC_URL

axelard tx wasm execute $SERVICE_REGISTRY '{"authorize_workers":{"workers":["axelar1lsasewgqj7698e9a25v3c9kkzweee9cvejq5cs"],"service_name":'$SERVICE_NAME'}}' --from test --gas-prices 0.025uwasm --gas auto --gas-adjustment 2 -y --node $RPC_URL
axelard tx wasm execute $SERVICE_REGISTRY '{"declare_chain_support":{"service_name":'$SERVICE_NAME',"chains":["a"]}}' --from test --gas-prices 0.025uwasm --gas auto --gas-adjustment 2 -y --node $RPC_URL
axelard tx wasm execute $SERVICE_REGISTRY '{"bond_worker":{"service_name":'$SERVICE_NAME'}}' --amount 1uwasm --from test --gas-prices 0.025uwasm --gas auto --gas-adjustment 2 -y --node $RPC_URL

axelard tx wasm execute $VOTING_VERIFIER '{"verify_messages":{"messages":[{"cc_id":{"chain":"a","id":"0:0"},"source_address":"a","destination_chain":"a","destination_address":"a","payload_hash":"6493f8a93b0bff590d5535bbe16ad7475a58af7847581ab80ad1dad510cbe928"}]}}' --from test --gas-prices 0.025uwasm --gas auto --gas-adjustment 2 -y --node $RPC_URL
axelard tx wasm execute $VOTING_VERIFIER '{"vote":{"poll_id":"1","votes":[true]}}' --from test --gas-prices 0.025uwasm --gas auto --gas-adjustment 2 -y --node $RPC_URL
axelard tx wasm execute $VOTING_VERIFIER '{"end_poll":{"poll_id":"1"}}' --from test --gas-prices 0.025uwasm --gas auto --gas-adjustment 2 -y --node $RPC_URL

axelard query wasm contract-state smart $VOTING_VERIFIER '{"is_verified":{"messages":[{"cc_id":{"chain":"a","id":"0:0"},"source_address":"a","destination_chain":"a","destination_address":"a","payload_hash":"6493f8a93b0bff590d5535bbe16ad7475a58af7847581ab80ad1dad510cbe928"}]}}' --node $RPC_URL

#axelard tx wasm execute $VOTING_VERIFIER '{"confirm_message_statuses":{"message_statuses":[["2","success"]]}}' --from test --gas-prices 0.025uwasm --gas auto --gas-adjustment 2 -y --node $RPC_URL
#axelard tx wasm execute $VOTING_VERIFIER '{"vote":{"poll_id":"2","votes":[true]}}' --from test --gas-prices 0.025uwasm --gas auto --gas-adjustment 2 -y --node $RPC_URL
#axelard query wasm contract-state smart $VOTING_VERIFIER '{"is_confirmed":{"message_ids":["2"]}}' --node $RPC_URL
#axelard tx wasm execute $VOTING_VERIFIER '{"end_poll":{"poll_id":"2"}}' --from test --gas-prices 0.025uwasm --gas auto --gas-adjustment 2 -y --node $RPC_URL
#axelard query wasm contract-state smart $VOTING_VERIFIER '{"is_confirmed":{"message_ids":["2"]}}' --node $RPC_URL
