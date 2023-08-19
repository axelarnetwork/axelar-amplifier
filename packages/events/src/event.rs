use tendermint::block;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    BlockBegin(block::Height),
    BlockEnd(block::Height),
    Abci {
        event_type: String,
        attributes: serde_json::Map<String, serde_json::Value>,
    },
}
