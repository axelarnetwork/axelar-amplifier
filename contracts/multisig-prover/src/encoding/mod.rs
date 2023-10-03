mod abi;
mod bcs;

use axelar_wasm_std::operators::Operators;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint256};
use sha3::{Digest, Keccak256};

use connection_router::state::Message;
use multisig::{key::Signature, msg::Signer};

use crate::{
    error::ContractError,
    state::WorkerSet,
    types::{BatchID, Command, CommandBatch, CommandType},
};

#[cw_serde]
#[derive(Copy)]
pub enum Encoder {
    Abi,
    Bcs,
}

fn make_command(msg: Message, encoding: Encoder) -> Result<Command, ContractError> {
    Ok(Command {
        ty: CommandType::ApproveContractCall, // TODO: this would change when other command types are supported
        params: match encoding {
            Encoder::Abi => abi::command_params(
                msg.cc_id.chain.to_string(),
                msg.source_address.to_string(),
                msg.destination_address.to_string(),
                msg.payload_hash,
            )?,
            Encoder::Bcs => bcs::command_params(
                msg.cc_id.chain.to_string(),
                msg.source_address.to_string(),
                msg.destination_address.to_string(),
                msg.payload_hash,
            )?,
        },
        id: command_id(msg.cc_id.to_string()),
    })
}

fn make_transfer_operatorship(
    worker_set: WorkerSet,
    encoding: Encoder,
) -> Result<Command, ContractError> {
    let params = match encoding {
        Encoder::Abi => abi::transfer_operatorship_params(&worker_set),
        Encoder::Bcs => bcs::transfer_operatorship_params(&worker_set),
    }?;
    Ok(Command {
        ty: CommandType::TransferOperatorship,
        params,
        id: worker_set.hash(),
    })
}

pub struct CommandBatchBuilder {
    message_ids: Vec<String>,
    new_worker_set: Option<WorkerSet>,
    commands: Vec<Command>,
    destination_chain_id: Uint256,
    encoding: Encoder,
}

impl CommandBatchBuilder {
    pub fn new(destination_chain_id: Uint256, encoding: Encoder) -> Self {
        Self {
            message_ids: vec![],
            new_worker_set: None,
            commands: vec![],
            destination_chain_id,
            encoding,
        }
    }

    pub fn add_message(&mut self, msg: Message) -> Result<(), ContractError> {
        self.message_ids.push(msg.cc_id.to_string());
        self.commands.push(make_command(msg, self.encoding)?);
        Ok(())
    }

    pub fn add_new_worker_set(&mut self, worker_set: WorkerSet) -> Result<(), ContractError> {
        self.new_worker_set = Some(worker_set.clone());
        self.commands
            .push(make_transfer_operatorship(worker_set, self.encoding)?);
        Ok(())
    }

    pub fn build(self) -> Result<CommandBatch, ContractError> {
        let data = Data {
            destination_chain_id: self.destination_chain_id,
            commands: self.commands,
        };

        let id = BatchID::new(&self.message_ids, self.new_worker_set);

        Ok(CommandBatch {
            id,
            message_ids: self.message_ids,
            data,
            encoder: self.encoding,
        })
    }
}

impl CommandBatch {
    pub fn msg_digest(&self) -> HexBinary {
        match self.encoder {
            Encoder::Abi => abi::msg_digest(self),
            Encoder::Bcs => bcs::msg_digest(self),
        }
    }

    pub fn encode_execute_data(
        &self,
        quorum: Uint256,
        signers: Vec<(Signer, Option<Signature>)>,
    ) -> Result<HexBinary, ContractError> {
        match self.encoder {
            Encoder::Abi => abi::encode_execute_data(self, quorum, signers),
            Encoder::Bcs => bcs::encode_execute_data(self, quorum, signers),
        }
    }
}

#[cw_serde]
pub struct Data {
    pub destination_chain_id: Uint256,
    pub commands: Vec<Command>,
}

impl Data {
    pub fn encode(&self, encoder: Encoder) -> HexBinary {
        match encoder {
            Encoder::Abi => abi::encode(self),
            Encoder::Bcs => bcs::encode(self),
        }
    }
}

fn command_id(message_id: String) -> HexBinary {
    // TODO: we might need to change the command id format to match the one in core for migration purposes
    Keccak256::digest(message_id.as_bytes()).as_slice().into()
}

pub fn make_operators(worker_set: WorkerSet, encoder: Encoder) -> Operators {
    match encoder {
        Encoder::Abi => abi::make_operators(worker_set),
        Encoder::Bcs => bcs::make_operators(worker_set),
    }
}

#[cfg(test)]
mod test {

    use crate::test::test_data;

    use super::*;

    #[test]
    fn test_batch_id() {
        let messages = test_data::messages();
        let mut message_ids: Vec<String> =
            messages.iter().map(|msg| msg.cc_id.to_string()).collect();

        message_ids.sort();
        let res = BatchID::new(&message_ids, None);

        message_ids.reverse();
        let res2 = BatchID::new(&message_ids, None);

        assert_eq!(res, res2);
    }

    #[test]
    fn test_command_from_router_message() {
        let messages = test_data::messages();
        let router_message = messages.first().unwrap();

        let res = make_command(router_message.to_owned(), Encoder::Abi);
        assert!(res.is_ok());

        let res = res.unwrap();

        assert_eq!(
            res.id,
            HexBinary::from_hex("3ee2f8af2201994e3518c9ce6848774785c2eef3bdbf9f954899497616dd59af")
                .unwrap()
        );
        assert_eq!(res.ty, CommandType::ApproveContractCall);

        let mut router_message = router_message.to_owned();
        router_message.destination_address = "FF".repeat(32).parse().unwrap();
        let res = make_command(router_message.to_owned(), Encoder::Bcs);
        assert!(res.is_ok());

        let res = res.unwrap();

        assert_eq!(
            res.id,
            HexBinary::from_hex("3ee2f8af2201994e3518c9ce6848774785c2eef3bdbf9f954899497616dd59af")
                .unwrap()
        );
        assert_eq!(res.ty, CommandType::ApproveContractCall);
    }

    #[test]
    fn test_command_operator_transfer() {
        let new_worker_set = test_data::new_worker_set();
        let res = make_transfer_operatorship(new_worker_set.clone(), Encoder::Abi);
        assert!(res.is_ok());

        assert_eq!(res.unwrap().ty, CommandType::TransferOperatorship);
    }
}
