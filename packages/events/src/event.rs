use axelar_wasm_std::FnExt;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use error_stack::{IntoReport, Report, Result, ResultExt};
use serde_json::Value;
use tendermint::abci::EventAttribute;
use tendermint::{abci, block};

use crate::errors::DecodingError;
use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    BlockBegin(block::Height),
    BlockEnd(block::Height),
    Abci {
        event_type: String,
        attributes: serde_json::Map<String, serde_json::Value>,
    },
}

impl Event {
    pub fn block_begin(height: impl Into<block::Height>) -> Self {
        Event::BlockBegin(height.into())
    }

    pub fn block_end(height: impl Into<block::Height>) -> Self {
        Event::BlockEnd(height.into())
    }
}

impl TryFrom<abci::Event> for Event {
    type Error = Report<Error>;

    fn try_from(event: abci::Event) -> Result<Self, Error> {
        let abci::Event {
            kind: event_type,
            attributes,
        } = event;

        let attributes = attributes
            .iter()
            .map(try_into_kv_pair)
            .collect::<Result<_, _>>()?;

        Ok(Self::Abci {
            event_type,
            attributes,
        })
    }
}

fn try_into_kv_pair(attr: &EventAttribute) -> Result<(String, Value), Error> {
    decode_event_attribute(attr)
        .change_context(Error::DecodingAttributesFailed)
        .map(|(key, value)| {
            (
                key,
                serde_json::from_str(&value).unwrap_or_else(|_| value.into()),
            )
        })
}

fn decode_event_attribute(attribute: &EventAttribute) -> Result<(String, String), DecodingError> {
    Ok((
        base64_to_utf8(&attribute.key).into_report()?,
        base64_to_utf8(&attribute.value).into_report()?,
    ))
}

fn base64_to_utf8(base64_str: &str) -> std::result::Result<String, DecodingError> {
    Ok(STANDARD.decode(base64_str)?.then(String::from_utf8)?)
}
