# Event Verifier API

This package contains the API types and schema generation for the event-verifier contract. This package is meant to be consumed by the contract itself, ampd and any external callers.
The contract accepts arbitrary events to verify as a JSON string. This JSON represents Rust types defined in this package. There is a JSON schema generated from the Rust types that external callers can use.

## Overview

The `event-verifier-api` package provides:

- **API Types**: All the message types, structs, and enums used by the event-verifier contract
- **Schema Generation**: Tools to generate JSON schemas for the contract and EventData
- **Client Support**: Types for building contract clients

## Structure

```
src/
├── lib.rs          # Main library entry point
├── msg.rs          # API types (InstantiateMsg, ExecuteMsg, QueryMsg, etc.)
├── evm.rs          # EVM-specific types (Event, TransactionDetails)
└── bin/
    ├── schema.rs           # Contract schema generator
    └── schema_generator.rs # EventData JSON schema generator
```

## Available Queries

The contract supports the following queries:

- **`Poll`**: Get information about a specific poll by ID
- **`EventsStatus`**: Get verification status for a list of events
- **`CurrentThreshold`**: Get the current voting threshold required for verification
- **`CurrentFee`**: Get the current fee required to call `verify_events`

## Available Execute Messages

- **`Vote`**: Cast votes for a specific poll
- **`VerifyEvents`**: Submit events for verification (requires fee payment)
- **`UpdateVotingThreshold`**: Update the voting threshold (governance only)
- **`UpdateFee`**: Update the required fee (admin only)
- **`Withdraw`**: Withdraw accumulated fees (admin only)

## Event Data Structure

The contract accepts events in a flexible format defined by the `EventData` enum. Currently supported:

- **EVM Events**: Ethereum-compatible blockchain events with transaction details

For detailed schema information, see [`EVENT_DATA_SCHEMA.md`](./EVENT_DATA_SCHEMA.md).

### Generating Schemas

```bash
# Generate contract schema
cargo run --bin event-verifier-schema

# Generate EventData JSON schema
cargo run --bin schema_generator
```

### Integration

New chain integrations should add their event format to the `EventData` struct in msg.rs, and regenerate the schema. A corresponding ampd handler needs to be written, though that does not need to be upstreamed. The contract itself can remain unchanged as new event formats are added.

## Usage Example

```rust
use event_verifier_api::{EventToVerify, EventData, ExecuteMsg, QueryMsg};

// Create an event to verify
let event_data = EventData::Evm {
    transaction_hash: "0x7cedbb3799cd99636045c84c5c55aef8a138f107ac8ba53a08cad1070ba4385b".parse().unwrap(),
    transaction_details: None,
    events: vec![/* ... */],
};

let event = EventToVerify {
    source_chain: "ethereum".into(),
    event_data: serde_json::to_string(&event_data).unwrap(),
};

// Query current fee
let fee_query = QueryMsg::CurrentFee;

// Submit events for verification
let verify_msg = ExecuteMsg::VerifyEvents(vec![event]);
```