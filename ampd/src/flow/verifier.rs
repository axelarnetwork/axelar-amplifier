use axelar_wasm_std::voting::Vote;
use serde::{Serialize, Deserialize};

use crate::flow::grpc::flow::{Event, TransactionResultResponse};

const CONTRACT_CALL_EVENT: &str = "AxelarGateway.ContractCall";

#[derive(Deserialize, Debug)]
pub struct Message {
  pub tx_id: String,
  pub event_index: u32,
  pub destination_address: String,
  pub destination_chain: connection_router::state::ChainName,
  pub source_address: String,
  pub payload_hash: String,
}

#[derive(Deserialize)]
struct ContractCall {
  pub sender: String,
  pub destination_chain: String,
  pub destination_address: String,
  pub payload_hash: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct FlowEventPayload {
  value: PayloadValue,
  r#type: String
}

#[derive(Serialize, Deserialize, Debug)]
struct PayloadValue {
  id: String,
  fields: Vec<CadenceJsonKeyValue>
}

#[derive(Serialize, Deserialize, Debug)]
struct CadenceJsonKeyValue {
  value: CadenceJsonValue,
  name: String
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
enum CadenceJsonValue {
  StringValue(CadenceJsonStringValue),
  ArrayValue(CadenceJsonArrayValue)
}

#[derive(Serialize, Deserialize, Debug)]
struct CadenceJsonArrayValue {
  value: Vec<CadenceJsonStringValue>,
  r#type: String
}

#[derive(Serialize, Deserialize, Debug)]
struct CadenceJsonStringValue {
  value: String,
  r#type: String
}

// Event type is in the form of: A.<gateway_address>.<contract_name>.<event_name>
// gateway_address does not contain 0x prefix in the event type
fn call_contract_type(gateway_address: &str) -> String {
  format!("A.{}.{}", sans_prefix(gateway_address), CONTRACT_CALL_EVENT)
    .parse()
    .expect("failed to parse struct tag")
}

impl PartialEq<&Message> for &Event {
  fn eq(&self, msg: &&Message) -> bool {
    match serde_json::from_slice::<FlowEventPayload>(&self.payload) {
      Ok(flow_event_payload) => {
        let contract_call = parse_flow_event_payload(&flow_event_payload);
        match contract_call {
          Some(contract_call) => {
            contract_call.sender == msg.source_address
            && msg.destination_chain == contract_call.destination_chain
            && contract_call.destination_address == msg.destination_address
            && contract_call.payload_hash == msg.payload_hash
          }
          None => false,
        }
      }
      _ => false,
    }
  }
}

fn find_event(
  transaction_block: &TransactionResultResponse,
  event_index: u32,
) -> Option<&Event> {
  transaction_block
    .events
    .iter()
    .find(|event| event.event_index == event_index)
}

fn sans_prefix(flow_address: &str) -> &str {
  flow_address.strip_prefix("0x").unwrap_or(flow_address)
}

fn parse_flow_event_payload(payload: &FlowEventPayload) -> Option<ContractCall> {
  let mut sender = String::new();
  let mut destination_chain = String::new();
  let mut destination_address = String::new();
  let mut payload_hash = String::new();

  for field in &payload.value.fields {
    if let CadenceJsonValue::StringValue(string_value) = &field.value {
      match field.name.as_str() {
        "sender" => sender = string_value.value.clone(),
        "destinationChain" => destination_chain = string_value.value.clone(),
        "destinationContractAddress" => destination_address = string_value.value.clone(),
        "payloadHash" => payload_hash = string_value.value.clone(),
        _ => {}
      }
    }
  }

  if sender.is_empty() || destination_chain.is_empty() || destination_address.is_empty() || payload_hash.is_empty() {
    None
  } else {
    Some(ContractCall {
      sender,
      destination_chain,
      destination_address,
      payload_hash,
    })
  }
}

pub fn verify_message(
  gateway_address: &str,
  transaction_block: &TransactionResultResponse,
  message: &Message,
) -> Vote {
  match find_event(transaction_block, message.event_index) {
    Some(event)
      if hex::encode(transaction_block.transaction_id.clone()) == message.tx_id
        && event.r#type == call_contract_type(gateway_address)
        && event == message =>
    {
      Vote::SucceededOnChain
    }
    _ => Vote::NotFound,
  }
}

#[cfg(test)]
mod tests {
  use axelar_wasm_std::voting::Vote;
  use rand::{Rng, rngs::OsRng};
  use crate::flow::grpc::flow::{Event, TransactionResultResponse, Metadata};

  use crate::flow::verifier::{
    verify_message,
    call_contract_type,
    Message,
    PayloadValue,
    FlowEventPayload,
    CadenceJsonValue,
    CadenceJsonKeyValue,
    CadenceJsonStringValue,
  };
  use crate::types::EVMAddress;

  #[test]
  fn should_not_verify_msg_if_tx_id_does_not_match() {
    let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_block();

    msg.tx_id = random_flow_tx_id();
    assert_eq!(
      verify_message(&gateway_address, &tx_receipt, &msg),
      Vote::NotFound
    );
  }

  #[test]
  fn should_not_verify_msg_if_event_index_does_not_match() {
    let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_block();

    msg.event_index = rand::random::<u32>();
    assert_eq!(
      verify_message(&gateway_address, &tx_receipt, &msg),
      Vote::NotFound
    );
  }

  #[test]
  fn should_not_verify_msg_if_source_address_does_not_match() {
    let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_block();

    msg.source_address = random_flow_address();
    assert_eq!(
      verify_message(&gateway_address, &tx_receipt, &msg),
      Vote::NotFound
    );
  }

  #[test]
  fn should_not_verify_msg_if_destination_chain_does_not_match() {
    let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_block();

    msg.destination_chain = "ethereum-1".parse().unwrap();
    assert_eq!(
      verify_message(&gateway_address, &tx_receipt, &msg),
      Vote::NotFound
    );
  }

  #[test]
  fn should_not_verify_msg_if_destination_address_does_not_match() {
    let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_block();

    msg.destination_address = EVMAddress::random().to_string();
    assert_eq!(
      verify_message(&gateway_address, &tx_receipt, &msg),
      Vote::NotFound
    );
  }

  #[test]
  fn should_not_verify_msg_if_payload_hash_does_not_match() {
    let (gateway_address, tx_receipt, mut msg) = get_matching_msg_and_tx_block();

    msg.payload_hash = random_flow_tx_id();
    assert_eq!(
      verify_message(&gateway_address, &tx_receipt, &msg),
      Vote::NotFound
    );
  }

  #[test]
  fn should_verify_msg_if_correct() {
    let (gateway_address, tx_block, msg) = get_matching_msg_and_tx_block();
    assert_eq!(
      verify_message(&gateway_address, &tx_block, &msg),
      Vote::SucceededOnChain
    );
  }

  fn random_flow_address() -> String {
    let mut rng = OsRng;
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes);

    format!("0x{}", hex::encode(bytes))
  }

  fn random_flow_tx_id() -> String {
    let mut rng = OsRng;
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);

    hex::encode(bytes)
  }

  fn get_matching_msg_and_tx_block() -> (String, TransactionResultResponse, Message) {
    let gateway_address = random_flow_address();

    let msg = Message {
      tx_id: random_flow_tx_id(),
      event_index: rand::random::<u32>(),
      source_address: random_flow_address(),
      destination_chain: "ethereum-2".parse().unwrap(),
      destination_address: format!("0x{:x}", EVMAddress::random()).parse().unwrap(),
      payload_hash: random_flow_tx_id(),
    };

    let event = Event {
      r#type: call_contract_type(&gateway_address),
      transaction_id: hex::decode(msg.tx_id.clone()).unwrap(),
      transaction_index: rand::random::<u32>(),
      event_index: msg.event_index,
      payload: get_testing_flow_event_payload(&msg)
    };

    let metadata = Metadata {
      latest_finalized_block_id: hex::decode(random_flow_tx_id()).unwrap(),
      latest_finalized_height: rand::random::<u64>(),
      node_id: hex::decode(random_flow_tx_id()).unwrap()
    };

    let transaction_response = TransactionResultResponse {
      status: 4,
      status_code: 0,
      error_message: "".to_string(),
      events: vec![event],
      block_id: hex::decode(random_flow_tx_id()).unwrap(),
      transaction_id: hex::decode(msg.tx_id.clone()).unwrap(),
      collection_id: hex::decode(random_flow_tx_id()).unwrap(),
      block_height: rand::random::<u64>(),
      metadata: Some(metadata)
    };

    (gateway_address, transaction_response, msg)
  }

  fn get_testing_flow_event_payload(msg: &Message) -> Vec<u8> {
    let event_payload = FlowEventPayload {
      value: PayloadValue {
        id: "A.48fff76f366d0864.AxelarGateway.ContractCall".to_string(),
        fields: vec![
          CadenceJsonKeyValue {
            value: CadenceJsonValue::StringValue(CadenceJsonStringValue {
              value: msg.source_address.clone(),
              r#type: "Address".to_string(),
            }),
            name: "sender".to_string(),
          },
          CadenceJsonKeyValue {
            value: CadenceJsonValue::StringValue(CadenceJsonStringValue {
              value: msg.destination_chain.to_string(),
              r#type: "String".to_string(),
            }),
            name: "destinationChain".to_string(),
          },
          CadenceJsonKeyValue {
            value: CadenceJsonValue::StringValue(CadenceJsonStringValue {
              value: msg.destination_address.clone(),
              r#type: "String".to_string(),
            }),
            name: "destinationContractAddress".to_string(),
          },
          CadenceJsonKeyValue {
            value: CadenceJsonValue::StringValue(CadenceJsonStringValue {
              value: msg.payload_hash.clone(),
              r#type: "String".to_string(),
            }),
            name: "payloadHash".to_string(),
          },
        ],
      },
      r#type: "Event".to_string(),
    };
    serde_json::to_string(&event_payload).unwrap().into_bytes()
  }
}
