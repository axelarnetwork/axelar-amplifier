# EventData JSON Schema

This document describes the JSON schema for the `event_data` field in the event-verifier contract.

## Overview

The `event_data` field in the `EventToVerify` struct is a JSON string that contains serialized event data. This schema defines the structure that this JSON should follow.

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
  "Evm": {
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
  "Evm": {
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

See the `examples` section in the schema file for complete examples.

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
