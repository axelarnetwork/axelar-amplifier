use std::fs;
use std::path::Path;

// Import the actual types from the API
use axelar_wasm_std::fixed_size;
use cosmwasm_std::{HexBinary, Uint256};
use event_verifier_api::{Event, EventData, TransactionDetails};
use schemars::JsonSchema;

#[derive(Debug)]
enum SchemaGeneratorError {
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for SchemaGeneratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchemaGeneratorError::Io(e) => write!(f, "IO error: {}", e),
            SchemaGeneratorError::Json(e) => write!(f, "JSON serialization error: {}", e),
        }
    }
}

impl std::error::Error for SchemaGeneratorError {}

impl From<std::io::Error> for SchemaGeneratorError {
    fn from(error: std::io::Error) -> Self {
        SchemaGeneratorError::Io(error)
    }
}

impl From<serde_json::Error> for SchemaGeneratorError {
    fn from(error: serde_json::Error) -> Self {
        SchemaGeneratorError::Json(error)
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), SchemaGeneratorError> {
    // Generate the JSON schema for EventData using schemars
    let schema = generate_event_data_schema()?;

    // Write to a file
    let output_path = Path::new("event_data_schema.json");
    let json_string = serde_json::to_string_pretty(&schema)?;
    fs::write(output_path, json_string)?;

    println!("EventData JSON schema generated: {}", output_path.display());
    Ok(())
}

fn generate_event_data_schema() -> Result<serde_json::Value, SchemaGeneratorError> {
    // Use schemars to generate the schema from the actual Rust type
    let settings = schemars::gen::SchemaSettings::default();
    let mut generator = schemars::gen::SchemaGenerator::new(settings);
    let schema = EventData::json_schema(&mut generator);

    // Get the definitions from the generator
    let definitions = generator.definitions();

    // Convert to serde_json::Value and add metadata
    let mut schema_value = serde_json::to_value(schema)?;

    // Add definitions
    if let serde_json::Value::Object(ref mut map) = schema_value {
        map.insert(
            "definitions".to_string(),
            serde_json::to_value(definitions)?,
        );
    }

    // Add schema metadata
    if let serde_json::Value::Object(ref mut map) = schema_value {
        map.insert(
            "$schema".to_string(),
            serde_json::Value::String("http://json-schema.org/draft-07/schema#".to_string()),
        );
        map.insert(
            "title".to_string(),
            serde_json::Value::String("EventData Schema".to_string()),
        );
        map.insert("description".to_string(), serde_json::Value::String("JSON schema for the EventData structure that gets serialized into the event_data string field".to_string()));

        // Add examples by constructing real Rust types and serializing them
        let examples: Vec<serde_json::Value> = build_evm_examples()
            .into_iter()
            .map(|ex| serde_json::to_value(&ex).expect("serialize example"))
            .collect();
        map.insert("examples".to_string(), serde_json::Value::Array(examples));
    }

    Ok(schema_value)
}

fn hex20(s: &str) -> fixed_size::HexBinary<20> {
    fixed_size::HexBinary::<20>::try_from(
        HexBinary::from_hex(s).expect("invalid hex for 20-byte value"),
    )
    .expect("invalid length for 20-byte value")
}

fn hex32(s: &str) -> fixed_size::HexBinary<32> {
    fixed_size::HexBinary::<32>::try_from(
        HexBinary::from_hex(s).expect("invalid hex for 32-byte value"),
    )
    .expect("invalid length for 32-byte value")
}

fn hexbin(s: &str) -> HexBinary {
    HexBinary::from_hex(s).expect("invalid hex for HexBinary")
}

fn build_evm_examples() -> Vec<EventData> {
    let example_evm_no_tx = EventData::Evm {
        transaction_hash: hex32("7cedbb3799cd99636045c84c5c55aef8a138f107ac8ba53a08cad1070ba4385b"),
        transaction_details: None,
        events: vec![Event {
            contract_address: hex20("5425890298aed601595a70ab815c96711a31bc65"),
            event_index: 0,
            topics: vec![
                hex32("8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"),
                hex32("0000000000000000000000006aa9f4fe1ce6fa00f06f2fe4bb6365180bc3a621"),
                hex32("000000000000000000000000e233862be9e5ff645e25ce6a001cf1fec28097c8"),
            ],
            data: hexbin("000000000000000000000000000000000000000000000000000000aa910f88c4"),
        }],
    };

    let example_evm_with_tx = EventData::Evm {
        transaction_hash: hex32(
            "7cedbb3799cd99636045c84c5c55aef8a138f107ac8ba53a08cad1070ba4385b",
        ),
        transaction_details: Some(TransactionDetails {
            calldata: hexbin(
                "a9059cbb000000000000000000000000e233862be9e5ff645e25ce6a001cf1fec28097c800000000000000000000000000000000000000000000000000000000aa910f88c4",
            ),
            from: hex20("6aa9f4fe1ce6fa00f06f2fe4bb6365180bc3a621"),
            to: hex20("5425890298aed601595a70ab815c96711a31bc65"),
            value: Uint256::from(0u128),
        }),
        events: vec![Event {
            contract_address: hex20("5425890298aed601595a70ab815c96711a31bc65"),
            event_index: 0,
            topics: vec![
                hex32("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"),
                hex32("0000000000000000000000006aa9f4fe1ce6fa00f06f2fe4bb6365180bc3a621"),
                hex32("000000000000000000000000e233862be9e5ff645e25ce6a001cf1fec28097c8"),
            ],
            data: hexbin("000000000000000000000000000000000000000000000000000000aa910f88c4"),
        }],
    };

    vec![example_evm_no_tx, example_evm_with_tx]
}
