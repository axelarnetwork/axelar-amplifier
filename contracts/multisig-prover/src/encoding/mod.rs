pub mod abi;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, Uint256};
use sha3::{Digest, Keccak256};

use connection_router::msg::Message;
use multisig::{key::Signature, msg::Signer};

use crate::{
    error::ContractError,
    state::WorkerSet,
    types::{BatchID, Command, CommandBatch, CommandType},
};

#[cw_serde]
#[derive(Copy)]
pub enum EncodingScheme {
    Abi,
    Bcs,
}

fn make_command(msg: Message, encoding_scheme: EncodingScheme) -> Result<Command, ContractError> {
    Ok(Command {
        ty: CommandType::ApproveContractCall, // TODO: this would change when other command types are supported
        params: match encoding_scheme {
            EncodingScheme::Abi => abi::command_params(
                msg.source_chain,
                msg.source_address,
                msg.destination_address,
                msg.payload_hash,
            )?,
            EncodingScheme::Bcs => todo!(),
        },
        id: command_id(msg.id),
    })
}

fn make_transfer_operatorship(
    worker_set: WorkerSet,
    encoding_scheme: EncodingScheme,
) -> Result<Command, ContractError> {
    let params = match encoding_scheme {
        EncodingScheme::Abi => abi::transfer_operatorship_params(&worker_set),
        EncodingScheme::Bcs => {
            todo!()
        }
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
    encoding: EncodingScheme,
}

impl CommandBatchBuilder {
    pub fn new(destination_chain_id: Uint256, encoding: EncodingScheme) -> Self {
        Self {
            message_ids: vec![],
            new_worker_set: None,
            commands: vec![],
            destination_chain_id,
            encoding,
        }
    }

    pub fn add_message(&mut self, msg: Message) -> Result<(), ContractError> {
        self.message_ids.push(msg.id.clone());
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
            encoding: self.encoding,
        })
    }
}

impl CommandBatch {
    pub fn msg_to_sign(&self) -> HexBinary {
        match self.encoding {
            EncodingScheme::Abi => abi::msg_to_sign(self),
            EncodingScheme::Bcs => todo!(),
        }
    }

    pub fn encode_execute_data(
        &self,
        quorum: Uint256,
        signers: Vec<(Signer, Option<Signature>)>,
    ) -> Result<HexBinary, ContractError> {
        match self.encoding {
            EncodingScheme::Abi => abi::encode_execute_data(self, quorum, signers),
            EncodingScheme::Bcs => todo!(),
        }
    }
}

#[cw_serde]
pub struct Data {
    pub destination_chain_id: Uint256,
    pub commands: Vec<Command>,
}

impl Data {
    pub fn encode(&self, encoding: EncodingScheme) -> HexBinary {
        match encoding {
            EncodingScheme::Abi => abi::encode(self),
            EncodingScheme::Bcs => todo!(),
        }
    }
}

fn command_id(message_id: String) -> HexBinary {
    // TODO: we might need to change the command id format to match the one in core for migration purposes
    Keccak256::digest(message_id.as_bytes()).as_slice().into()
}

#[cfg(test)]
mod test {

    use crate::test::test_data;

    use super::*;

    #[test]
    fn test_batch_id() {
        let messages = test_data::messages();
        let mut message_ids: Vec<String> = messages.iter().map(|msg| msg.id.clone()).collect();

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

        let res = make_command(router_message.to_owned(), EncodingScheme::Abi);
        assert!(res.is_ok());

        let res = res.unwrap();

        assert_eq!(
            res.id,
            HexBinary::from_hex("cdf61b5aa2024f5a27383b0785fc393c566eef69569cf5abec945794b097bb73")
                .unwrap() // https://axelarscan.io/gmp/0xc8a0024fa264d538986271bdf8d2901c443321faa33440b9f28e38ea28e6141f
        );
        assert_eq!(res.ty, CommandType::ApproveContractCall);
    }

    #[test]
    fn test_command_operator_transfer() {
        let new_worker_set = test_data::new_worker_set();
        let res = make_transfer_operatorship(new_worker_set.clone(), EncodingScheme::Abi);
        assert!(res.is_ok());

        assert_eq!(res.unwrap().ty, CommandType::TransferOperatorship);
    }
}
