//! This crate contains the generated code from the Aleo program used in the Aleo gateway.
//! To generate the code this crate is used: https://github.com/eigerco/axelar-aleo/tree/leo-structs-macro
//!
//! When the above mentioned is reviews we can use it directly as a dependency and always read aleo
//! programs from this repo, to generate the code.
//!
//! The current generated code is generated from this Aleo program:
//!
//! ```aleo
//! program foobar.aleo {
//!     struct ApproveMessagesInputs {
//!         weighted_signers: WeightedSigners,
//!         signatures: [[signature; 14]; 2],
//!         messages: [[group; 24]; 2],
//!     }
//!
//!     struct RotateSignersInputs {
//!         weighted_signers: WeightedSigners,
//!         signatures: [[signature; 14]; 2],
//!         payload: WeightedSigners,
//!     }
//!
//!     struct ValidateMessageInputs {
//!         message_hash: group,
//!         message_batch_hash: group,
//!     }
//!
//!     struct WeightedSigners {
//!         signers: [[WeightedSigner; 14]; 2],
//!         quorum: u128,
//!         nonce: u64
//!     }
//!
//!     struct WeightedSigner {
//!         addr: address,
//!         weight: u128,
//!     }
//!
//!     struct PayloadDigest {
//!         domain_separator: [u128; 2],
//!         signer: WeightedSigners,
//!         data_hash: group,
//!     }
//!
//!     struct SignersRotated {
//!         new_signers_hash: group,
//!         new_signers_data: WeightedSigners,
//!     }
//!
//!     struct Message {
//!         source_chain: [u128; 2],
//!         message_id: [u128; 8],
//!         source_address: [u128; 6],
//!         contract_address: address,
//!         payload_hash: group,
//!     }
//!
//!     struct ContractCall {
//!         caller: address,
//!         destination_chain: [u128; 2],
//!         destination_address: [u128; 6],
//!         payload_hash: field,
//!     }
//!
//!     // The following struct are constructed by multisig-prover
//!
//!     struct ExecuteData {
//!         proof: Proof,
//!         message: Messages,
//!     }
//!
//!     struct Proof {
//!         weighted_signers: WeightedSigners,
//!         signatures: [[signature; 14]; 2],
//!     }
//!
//!     struct Messages {
//!         messages: [[Message; 24]; 2],
//!     }
//!
//!     // The following structs are for ITS
//!
//!     // axelarinterchaintokenhub.aleo
//!     // Handle issue with generics
//!     struct DeployInterchainToken {
//!         its_token_id: [u128; 2],
//!         name: u128,
//!         symbol: u128,
//!         decimals: u8,
//!         minter: [u128; 6],
//!     }
//!
//!     // From the remote chain to Aleo
//!     struct FromRemoteDeployInterchainToken {
//!         its_token_id: [u128; 2],
//!         name: u128,
//!         symbol: u128,
//!         decimals: u8,
//!         minter: address,                    // the minter address, if there is no minter the zero address should be used
//!     }
//!
//!     // This is the payload that will be sent to the Axelar ITS-hub
//!     struct RemoteDeployInterchainToken {
//!         payload: DeployInterchainToken,
//!         destination_chain: [u128; 2],
//!     }
//!
//!     struct IncomingInterchainTransfer {
//!         its_token_id: [u128; 2],
//!         source_address: [u128; 6],
//!         destination_address: address,       // the address that the token will be sent
//!         amount: u128,
//!     }
//!
//!     struct OutgoingInterchainTransfer {
//!         its_token_id: [u128; 2],
//!         source_address: address,
//!         destination_address: [u128; 6],
//!         amount: u128,
//!     }
//!
//!     struct ItsOutgoingInterchainTransfer {
//!         inner_message: OutgoingInterchainTransfer,
//!         destination_chain: [u128; 2],
//!     }
//!
//!     // Used to provide minter approval for a remote chain.
//!     // A minter on Aleo, for a specific token, can approve a minter on a remote chain, for the same token.
//!     struct MinterApproval {
//!         approver: address,                  // the address that approves the minter, the approver should be a supply manager of the token
//!         minter: [u128; 6],                  // the minter address. The minter address will be at a remote chain
//!         its_token_id: [u128; 2],
//!         destination_chain: field,           // the hash of the destination chain name
//!     }
//!
//!     struct MinterProposal {
//!         proposer: address,                  // the address that proposes the new minter
//!         token_id: field,                    // the token id on Aleo
//!         new_minter: address,                // the new minter address
//!     }
//!
//!     // -- [ External struct ] ---------------------------------------------------------------------
//!     // TokenOwner is defined at [token_registry.aleo](https://github.com/demox-labs/aleo-standard-programs/blob/8bcc805da1399bd35c713155edeceee0096a7d31/token_registry/src/main.leo#L25)
//!     struct TokenOwner {
//!         account: address,
//!         token_id: field
//!     }
//!
//!     // deployfromremotechain.aleo
//!     struct ItsMessageDeployInterchainToken {
//!         inner_message: FromRemoteDeployInterchainToken,
//!         source_chain: [u128; 2]
//!     }
//!
//!     // incomingtransfermint.aleo
//!     // incomingtransferunlock.aleo
//!     struct ItsIncomingInterchainTransfer {
//!         inner_message: IncomingInterchainTransfer,
//!         source_chain: [u128; 2],
//!     }
//!
//!     struct RegisterTokenMetadata {
//!         decimals: u8,
//!         token_address: field
//!     }
//!
//!     struct WrapedSentLinkToken {
//!         link_token: SentLinkToken,
//!         destination_chain: [u128; 2],
//!     }
//!
//!     struct SentLinkToken {
//!         token_id: [u128; 2],
//!         token_manager_type: u8,
//!         aleo_token_id: field,
//!         destination_token_address: [u128; 6],
//!         operator: [u128; 6],
//!     }
//!
//!     struct WrapedReceivedLinkToken {
//!         link_token: ReceivedLinkToken,
//!         source_chain: [u128; 2],
//!     }
//!
//!     struct ReceivedLinkToken {
//!         its_token_id: [u128; 2],
//!         token_manager_type: u8,
//!         source_token_address: [u128; 6], // change this from aleo token id to external token id
//!         destination_token_address: field, // In this case Aleo is the destination chain, and address is the address of the token, which on Aleo is the token id, which is a field.
//!         operator: address,
//!     }
//! ```

mod generated_structs;

pub use generated_structs::*;

pub mod constants {
    //! The following is a poor man’s solution.
    //!
    //! The ideal solution would be:
    //! 1. Define the constant in the Aleo gateway program
    //! 2. During code generation extract the constant value

    pub const DOMAIN_SEPARATOR_LEN: usize = 2;
    pub const DOMAIN_SEPARATOR: [u128; DOMAIN_SEPARATOR_LEN] = [
        77458889505116476800238291525522912105u128,
        212654606198768313326909807475703735288u128,
    ];

    pub const SINGATURES_PER_CHUNK: usize = 14;
    pub const SIGNATURE_CHUNKS: usize = 2;
    pub const MAX_SIGNATURES: usize = SINGATURES_PER_CHUNK * SIGNATURE_CHUNKS;

    pub const MESSAGES_PER_CHUNK: usize = 24;
    pub const MESSAGE_CHUNKS: usize = 2;
    pub const MAX_MESSAGES: usize = MESSAGES_PER_CHUNK * MESSAGE_CHUNKS;

    pub const CHAIN_NAME_LEN: usize = 2;
    pub const EXTERNAL_ADDRESS_LEN: usize = 6;
    pub const MESSAGE_ID_LEN: usize = 8;
    pub const TOKEN_ID_LEN: usize = 2;

    // -- [ Token Manager Types ] -----------------------------------------------------------------
    pub const NATIVE_INTERCHAIN_TOKEN: u8 = 0u8;
    pub const MINT_BURN_FROM: u8 = 1u8;
    pub const LOCK_UNLOCK: u8 = 2u8;
    pub const LOCK_UNLOCK_FEE: u8 = 3u8;
    pub const MINT_BURN: u8 = 4u8;
}
