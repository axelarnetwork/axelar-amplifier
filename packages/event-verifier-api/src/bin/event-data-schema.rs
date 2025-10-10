use std::fs;
use std::path::{Path, PathBuf};

// Import the actual types from the API
use axelar_wasm_std::fixed_size;
use chrono::Utc;
use clap::Parser;
use cosmwasm_std::{HexBinary, Uint256};
use event_verifier_api::evm::{Event, EvmEvent, TransactionDetails};
use event_verifier_api::EventData;
use schemars::schema_for;

/// EventData JSON Schema Generator
#[derive(Parser, Debug)]
#[command(author, version, about = "Generate JSON schema for EventData structure", long_about = None)]
struct Args {
    /// Optional output file path
    #[arg(help = "Output file path (default: event_data_schema.json)")]
    output_file: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
enum SchemaGeneratorError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

fn main() {
    let args = Args::parse();

    let output_file = args
        .output_file
        .unwrap_or_else(|| PathBuf::from("event_data_schema.json"));

    if let Err(e) = run(&output_file) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run(output_path: &Path) -> Result<(), SchemaGeneratorError> {
    // Generate the JSON schema for EventData using schemars
    let schema = generate_event_data_schema()?;

    // Write to a file
    let json_string = serde_json::to_string_pretty(&schema)?;
    fs::write(output_path, json_string)?;

    println!("EventData JSON schema generated: {}", output_path.display());
    Ok(())
}

fn generate_event_data_schema() -> Result<serde_json::Value, SchemaGeneratorError> {
    // Use schema_for! macro to generate the schema
    let schema = schema_for!(EventData);

    // Convert to serde_json::Value and add metadata
    let mut schema_value = serde_json::to_value(schema)?;

    // Add schema metadata
    if let serde_json::Value::Object(ref mut map) = schema_value {
        map.insert(
            "title".to_string(),
            serde_json::Value::String("EventData Schema".to_string()),
        );
        map.insert("description".to_string(), serde_json::Value::String("JSON schema for the EventData structure that gets serialized into the event_data string field".to_string()));

        // Add version and timestamp
        map.insert(
            "version".to_string(),
            serde_json::Value::String(env!("CARGO_PKG_VERSION").to_string()),
        );

        map.insert(
            "generated_at".to_string(),
            serde_json::Value::String(Utc::now().to_rfc3339()),
        );

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
    let example_evm_no_tx = EventData::Evm(EvmEvent {
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
    });

    let example_evm_with_tx = EventData::Evm(EvmEvent {
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
    });

    vec![example_evm_no_tx, example_evm_with_tx]
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn schema_file_is_up_to_date() {
        let schema_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("event_data_schema.json");

        // Read the existing schema file
        let existing_schema_str =
            fs::read_to_string(&schema_path).expect("event_data_schema.json should exist");
        let mut existing_schema: serde_json::Value = serde_json::from_str(&existing_schema_str)
            .expect("event_data_schema.json should be valid JSON");

        // Generate a fresh schema
        let mut fresh_schema =
            generate_event_data_schema().expect("schema generation should succeed");

        // Remove the generated_at timestamp from both schemas for comparison
        if let serde_json::Value::Object(ref mut map) = existing_schema {
            map.remove("generated_at");
        }
        if let serde_json::Value::Object(ref mut map) = fresh_schema {
            map.remove("generated_at");
        }

        // Compare the schemas
        assert_eq!(
            fresh_schema, existing_schema,
            "event_data_schema.json is out of date. Please run: cargo run --bin event-data-schema"
        );
    }
}
