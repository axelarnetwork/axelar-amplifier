use axelar_wasm_std::msg_id::HexTxHash;
use axelar_wasm_std::{nonempty, IntoContractError};
use cosmwasm_std::{StdError, Uint256};
use cw_utils::ParseReplyError;
use interchain_token_service::TokenId;
use router_api::{ChainName, ChainNameRaw, CrossChainId};
use thiserror::Error;
use xrpl_types::error::XRPLError;
use xrpl_types::msg::XRPLMessage;
use xrpl_types::types::{AxelarSigner, XRPLPath, XRPLToken, XRPLTxStatus};

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error("division by zero error")]
    DivisionByZero,

    #[error("empty signer public keys")]
    EmptySignerPublicKeys,

    #[error("failed to build verifier set")]
    FailedToBuildVerifierSet,

    #[error("failed to get token instance decimals for token with ID {token_id} on chain {chain} from gateway")]
    FailedToGetTokenInstanceDecimals {
        token_id: TokenId,
        chain: ChainNameRaw,
    },

    #[error("failed to get token with ID {0} from gateway")]
    FailedToGetXrplToken(TokenId),

    #[error("failed to get XRP token ID from gateway")]
    FailedToGetXrpTokenId,

    #[error("failed to get outgoing messages from gateway")]
    FailedToGetMessages,

    #[error("failed to get messages status from gateway. messages: {0:?}")]
    FailedToGetMessagesStatus(Vec<XRPLMessage>),

    #[error("failed to get message status from gateway. message: {0:?}")]
    FailedToGetMessageStatus(XRPLMessage),

    #[error("failed to get multisig session with ID {0} from multisig")]
    FailedToGetMultisigSession(u64),

    #[error("failed to serialize")]
    FailedToSerialize,

    #[error("failed to start multisig session: {reason}")]
    FailedToStartMultisigSession { reason: String },

    #[error("failed to update admin")]
    FailedToUpdateAdmin,

    #[error("invalid amount: {reason}")]
    InvalidAmount { reason: String },

    #[error("invalid blob length")]
    InvalidBlobLength,

    #[error("invalid contract reply: {reason}")]
    InvalidContractReply { reason: String },

    #[error("invalid destination address")]
    InvalidDestinationAddress,

    #[error("invalid destination chain '{actual}', expected '{expected}'")]
    InvalidDestinationChain {
        actual: ChainName,
        expected: ChainName,
    },

    #[error("invalid message ID {0}")]
    InvalidMessageId(String),

    #[error("invalid payload")]
    InvalidPayload,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("invalid signer {0:?}")]
    InvalidSigner(AxelarSigner),

    #[error("invalid signer public keys")]
    InvalidSignerPublicKeys,

    #[error("invalid transfer amount {amount} from chain {source_chain}")]
    InvalidTransferAmount {
        source_chain: ChainNameRaw,
        amount: Uint256,
    },

    #[error("invalid transaction status {0}")]
    InvalidTxStatus(XRPLTxStatus),

    #[error("transaction ID {expected} did not match reconstructed transaction ID {actual}")]
    TxIdMismatch {
        actual: HexTxHash,
        expected: HexTxHash,
    },

    #[error("local token {0} not registered")]
    LocalTokenNotRegistered(XRPLToken),

    #[error("failed to fetch message status")]
    MessageStatusNotFound,

    #[error("outgoing message {0} not found on gateway")]
    MessageNotFound(CrossChainId),

    #[error("no available tickets")]
    NoAvailableTickets,

    #[error("no verifier set stored")]
    NoVerifierSet,

    #[error("no verifier set to confirm")]
    NoVerifierSetToConfirm,

    #[error(transparent)]
    NonEmptyError(#[from] nonempty::Error),

    #[error("not enough verifiers")]
    NotEnoughVerifiers,

    #[error("overflow error")]
    Overflow,

    #[error(transparent)]
    ParseReply(#[from] ParseReplyError),

    #[error("payload hash mismatch")]
    PayloadHashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },

    #[error("payment already has active signing session with ID {0}")]
    PaymentAlreadyHasActiveSigningSession(u64),

    #[error("payment already has completed signing session with ID {0}")]
    PaymentAlreadyHasCompletedSigningSession(u64),

    #[error("payment for {0} already succeeded")]
    PaymentAlreadySucceeded(CrossChainId),

    #[error("payment without original cross-chain ID")]
    PaymentMissingCrossChainId,

    #[error("quorum does not fit in u32: {0}")]
    QuorumTooLarge(u64),

    #[error("failed to serialize the response")]
    SerializeResponse,

    #[error("confirmed SignerListSet transaction does not match expected verifier set")]
    SignerListMismatch,

    #[error(transparent)]
    Std(#[from] StdError),

    #[error("ticket count threshold has not been reached")]
    TicketCountThresholdNotReached,

    #[error("too many available tickets")]
    TooManyAvailableTickets,

    #[error("too many paths in PathSet")]
    TooManyPaths,

    #[error("too many steps in PathSet path: {0}")]
    TooManyPathSteps(XRPLPath),

    #[error("too many verifiers")]
    TooManyVerifiers,

    #[error("token {0} not local")]
    TokenNotLocal(XRPLToken),

    #[error("trust line already exists for token {0}")]
    TrustLineAlreadyExists(XRPLToken),

    #[error("transaction status is already confirmed")]
    TxStatusAlreadyConfirmed,

    #[error("transaction status is not pending")]
    TxStatusNotPending,

    #[error("transaction status is still unknown")]
    TxStatusUnknown,

    #[error("transaction status is still being verified")]
    TxStatusVerificationInProgress,

    #[error("a verifier set confirmation already in progress")]
    VerifierSetConfirmationInProgress,

    #[error("verifier set has not changed sufficiently since last update")]
    VerifierSetUnchanged,

    #[error(transparent)]
    XRPLTypeConversionError(#[from] XRPLError),

    #[error("zero paths given in PathSet")]
    ZeroPaths,

    #[error("zero steps given in PathSet path: {0}")]
    ZeroPathSteps(XRPLPath),
}

impl From<ContractError> for StdError {
    fn from(value: ContractError) -> Self {
        Self::generic_err(value.to_string())
    }
}
