# EventData JSON Schema

This document describes the JSON schema for the `event_data` field in the event-verifier contract.

## Overview

The `event_data` field in the `EventToVerify` struct is a JSON string that contains serialized event data. Event data is unique to each type of chain or VM. This schema defines the structure that this JSON should follow. This schema can be used to verify the event data is formatted correctly. The format is opaque to the contract, and malformed data will not be rejected by the contract itself, but will simply fail to verify (ampd will vote no).

## Schema File

The complete JSON schema is available in [`event_data_schema.json`](./event_data_schema.json).

## Usage

### For API Callers

When calling the event-verifier contract, you need to serialize your event data as a JSON string and pass it as the `event_data` field. The JSON must conform to the schema defined in `event_data_schema.json`.

### For Validation

You can use the schema to validate your JSON before sending it to the contract:

```javascript
// Example using a JSON schema validator
const Ajv = require('ajv');
const schema = require('./event_data_schema.json');

const ajv = new Ajv();
const validate = ajv.compile(schema);

const eventData = {
  "evm": {
    "transaction_hash": "0x7cedbb3799cd99636045c84c5c55aef8a138f107ac8ba53a08cad1070ba4385b",
    "transaction_details": null,
    "events": [
      {
        "contract_address": "0x5425890298aed601595a70AB815c96711a31Bc65",
        "event_index": 0,
        "topics": [
          "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
        ],
        "data": "000000000000000000000000000000000000000000000000000000aa910f88c4"
      }
    ]
  }
};

const isValid = validate(eventData);
if (!isValid) {
  console.log('Validation errors:', validate.errors);
}
```

## Structure

The schema supports the following event types:

### EVM Events

```json
{
  "evm": {
    "transaction_hash": "0x...",
    "transaction_details": null | {
      "calldata": "hex_string_without_0x_prefix",
      "from": "0x...",
      "to": "0x...",
      "value": "decimal_string"
    },
    "events": [
      {
        "contract_address": "0x...",
        "event_index": 0,
        "topics": ["hex_string_without_0x_prefix"],
        "data": "hex_string_without_0x_prefix"
      }
    ]
  }
}
```

## Field Descriptions

### Transaction Hash (Required)
- `transaction_hash`: 32-byte transaction hash as a hex string with 0x prefix (e.g., "0x7cedbb3799cd99636045c84c5c55aef8a138f107ac8ba53a08cad1070ba4385b")

### Transaction Details (Optional)
- `calldata`: Hex-encoded transaction calldata (without 0x prefix)
- `from`: Ethereum address of the transaction sender (with 0x prefix)
- `to`: Ethereum address of the transaction recipient (with 0x prefix)
- `value`: Transaction value as a decimal string

### Events (Required)
- `contract_address`: Ethereum address of the contract that emitted the event (with 0x prefix)
- `event_index`: Index of the event in the transaction (0-based)
- `topics`: Array of 1-4 hex-encoded event topics (without 0x prefix)
- `data`: Hex-encoded event data (without 0x prefix)

## Examples

### Example 1: EVM Event without Transaction Details

```json
{
  "evm": {
    "transaction_hash": "0x7cedbb3799cd99636045c84c5c55aef8a138f107ac8ba53a08cad1070ba4385b",
    "transaction_details": null,
    "events": [
      {
        "contract_address": "0x5425890298aed601595a70AB815c96711a31Bc65",
        "data": "000000000000000000000000000000000000000000000000000000aa910f88c4",
        "event_index": 0,
        "topics": [
          "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
          "0000000000000000000000006aa9f4fe1ce6fa00f06f2fe4bb6365180bc3a621",
          "000000000000000000000000e233862be9e5ff645e25ce6a001cf1fec28097c8"
        ]
      }
    ]
  }
}
```

### Example 2: EVM Event with Transaction Details

```json
{
  "evm": {
    "transaction_hash": "0x7cedbb3799cd99636045c84c5c55aef8a138f107ac8ba53a08cad1070ba4385b",
    "transaction_details": {
      "calldata": "a9059cbb000000000000000000000000e233862be9e5ff645e25ce6a001cf1fec28097c800000000000000000000000000000000000000000000000000000000aa910f88c4",
      "from": "0x6aa9f4fe1ce6fa00f06f2fe4bb6365180bc3a621",
      "to": "0x5425890298aed601595a70AB815c96711a31Bc65",
      "value": "0"
    },
    "events": [
      {
        "contract_address": "0x5425890298aed601595a70AB815c96711a31Bc65",
        "data": "000000000000000000000000000000000000000000000000000000aa910f88c4",
        "event_index": 0,
        "topics": [
          "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
          "0000000000000000000000006aa9f4fe1ce6fa00f06f2fe4bb6365180bc3a621",
          "000000000000000000000000e233862be9e5ff645e25ce6a001cf1fec28097c8"
        ]
      }
    ]
  }
}
```

## Regenerating the Schema

To regenerate the schema after making changes to the EventData structure:

```bash
cargo run --bin schema_generator
```

This will update the `event_data_schema.json` file with the latest structure.

## How It Works

The schema is automatically generated from the actual Rust types using the `schemars` crate. This ensures that:

- The schema always matches the current Rust type definitions
- No manual maintenance is required when types change
- The schema includes proper validation patterns and descriptions
- All nested types (Event, TransactionDetails, etc.) are automatically included

The generator reads the `EventData` enum and its associated types directly from the contract code and generates a complete JSON Schema with definitions for all referenced types.
