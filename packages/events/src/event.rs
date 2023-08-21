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

impl Event {
    pub fn block_begin(height: impl Into<block::Height>) -> Self {
        Event::BlockBegin(height.into())
    }

    pub fn block_end(height: impl Into<block::Height>) -> Self {
        Event::BlockEnd(height.into())
    }
}
