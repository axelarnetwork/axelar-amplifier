use std::fs;
use std::path::Path;
use schemars::JsonSchema;
use serde_json;

// Import the actual types from the contract
use event_verifier::msg::{EventData, TransactionDetails, Event};

fn main() {
    // Generate the JSON schema for EventData using schemars
    let schema = generate_event_data_schema();
    
    // Write to a file
    let output_path = Path::new("event_data_schema.json");
    fs::write(output_path, serde_json::to_string_pretty(&schema).unwrap()).unwrap();
    
    println!("EventData JSON schema generated: {}", output_path.display());
}

fn generate_event_data_schema() -> serde_json::Value {
    // Use schemars to generate the schema from the actual Rust type
    let settings = schemars::gen::SchemaSettings::default();
    let mut generator = schemars::gen::SchemaGenerator::new(settings);
    let schema = EventData::json_schema(&mut generator);
    
    // Get the definitions from the generator
    let definitions = generator.definitions();
    
    // Convert to serde_json::Value and add metadata
    let mut schema_value = serde_json::to_value(schema).unwrap();
    
    // Add definitions
    if let serde_json::Value::Object(ref mut map) = schema_value {
        map.insert("definitions".to_string(), serde_json::to_value(definitions).unwrap());
    }
    
    // Add schema metadata
    if let serde_json::Value::Object(ref mut map) = schema_value {
        map.insert("$schema".to_string(), serde_json::Value::String("http://json-schema.org/draft-07/schema#".to_string()));
        map.insert("title".to_string(), serde_json::Value::String("EventData Schema".to_string()));
        map.insert("description".to_string(), serde_json::Value::String("JSON schema for the EventData structure that gets serialized into the event_data string field".to_string()));
        
        // Add examples
        let examples = vec![
            serde_json::json!({
                "evm": {
                    "transaction_details": null,
                    "events": [
                        {
                            "contract_address": "0x5425890298aed601595a70AB815c96711a31Bc65",
                            "event_index": 0,
                            "topics": [
                                "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
                                "0000000000000000000000006aa9f4fe1ce6fa00f06f2fe4bb6365180bc3a621",
                                "000000000000000000000000e233862be9e5ff645e25ce6a001cf1fec28097c8"
                            ],
                            "data": "000000000000000000000000000000000000000000000000000000aa910f88c4"
                        }
                    ]
                }
            }),
            serde_json::json!({
                "evm": {
                    "transaction_details": {
                        "calldata": "a9059cbb000000000000000000000000e233862be9e5ff645e25ce6a001cf1fec28097c800000000000000000000000000000000000000000000000000000000aa910f88c4",
                        "from": "0x6aa9f4fe1ce6fa00f06f2fe4bb6365180bc3a621",
                        "to": "0x5425890298aed601595a70AB815c96711a31Bc65",
                        "value": "0"
                    },
                    "events": [
                        {
                            "contract_address": "0x5425890298aed601595a70AB815c96711a31Bc65",
                            "event_index": 0,
                            "topics": [
                                "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                                "0000000000000000000000006aa9f4fe1ce6fa00f06f2fe4bb6365180bc3a621",
                                "000000000000000000000000e233862be9e5ff645e25ce6a001cf1fec28097c8"
                            ],
                            "data": "000000000000000000000000000000000000000000000000000000aa910f88c4"
                        }
                    ]
                }
            })
        ];
        map.insert("examples".to_string(), serde_json::Value::Array(examples));
    }
    
    schema_value
}
