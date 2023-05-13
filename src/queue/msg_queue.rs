// will remove in the next PR
#![allow(dead_code)]

use cosmrs::{Any, Gas};

#[derive(Default)]
pub struct MsgQueue {
    msgs: Vec<Any>,
    gas_cost: Gas,
}

impl MsgQueue {
    pub fn push(&mut self, msg: Any, gas_cost: Gas) {
        self.msgs.push(msg);
        self.gas_cost += gas_cost;
    }

    pub fn pop_all(&mut self) -> Vec<Any> {
        let msgs = self.msgs.clone();
        self.msgs.clear();
        self.gas_cost = 0;

        msgs
    }

    pub fn gas_cost(&self) -> Gas {
        self.gas_cost
    }
}

#[cfg(test)]
mod test {
    use cosmos_sdk_proto::Any;
    use cosmrs::bank::MsgSend;
    use cosmrs::tx::Msg;

    use super::MsgQueue;

    use crate::types::TMAddress;

    #[test]
    fn msg_queue_push_should_work() {
        let mut queue = MsgQueue::default();
        for gas_cost in 1..5 {
            queue.push(dummy_msg(), gas_cost);
        }

        assert_eq!(queue.gas_cost(), 10);
        assert_eq!(queue.msgs.len(), 4);
    }

    #[test]
    fn msg_queue_pop_all_should_work() {
        let mut queue = MsgQueue::default();
        for gas_cost in 1..5 {
            queue.push(dummy_msg(), gas_cost);
        }

        assert_eq!(queue.pop_all().len(), 4);
        assert_eq!(queue.gas_cost(), 0);
        assert_eq!(queue.msgs.len(), 0);
    }

    fn dummy_msg() -> Any {
        MsgSend {
            from_address: TMAddress::new("", &[1, 2, 3]).unwrap(),
            to_address: TMAddress::new("", &[4, 5, 6]).unwrap(),
            amount: vec![],
        }
        .to_any()
        .unwrap()
    }
}
