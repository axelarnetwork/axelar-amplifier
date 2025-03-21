use axelar_wasm_std::nonempty;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Uint256;
use interchain_token_service::TokenId;
use msgs_derive::EnsurePermissions;
use router_api::{ChainName, ChainNameRaw, CrossChainId, Message};
use xrpl_types::msg::{
    WithPayload, XRPLAddGasMessage, XRPLCallContractMessage, XRPLInterchainTransferMessage,
    XRPLMessage,
};
use xrpl_types::types::{
    xrpl_account_id_string, xrpl_currency_string, XRPLAccountId, XRPLCurrency, XRPLPaymentAmount,
    XRPLToken, XRPLTokenOrXrp,
};

#[cw_serde]
pub struct InstantiateMsg {
    /// Address that can execute all messages that either have unrestricted or admin permission level, such as Updateverifier set.
    /// Should be set to a trusted address that can react to unexpected interruptions to the contract's operation.
    pub admin_address: String,
    /// Address that can call all messages of unrestricted, admin and governance permission level, such as UpdateSigningThreshold.
    /// This address can execute messages that bypasses verification checks to rescue the contract if it got into an otherwise unrecoverable state due to external forces.
    /// On mainnet, it should match the address of the Cosmos governance module.
    pub governance_address: String,
    /// Address of the verifier contract on axelar associated with the source chain. E.g., the voting verifier contract.
    pub verifier_address: String,
    /// Address of the router contract on axelar.
    pub router_address: String,
    /// Address of the ITS Hub contract on axelar.
    pub its_hub_address: String,
    /// Chain name of the ITS Hub chain.
    pub its_hub_chain_name: ChainName,
    /// Chain name of the XRPL chain.
    pub chain_name: ChainName,
    /// Address of the Axelar Gateway multisig account on XRPL.
    #[serde(with = "xrpl_account_id_string")]
    #[schemars(with = "String")] // necessary attribute in conjunction with #[serde(with ...)]
    pub xrpl_multisig_address: XRPLAccountId,
}

#[cw_serde]
pub struct TokenMetadata {
    /// The name of the token
    pub name: nonempty::String,
    /// The symbol of the token
    pub symbol: nonempty::String,
}

#[cw_serde]
pub struct LinkToken {
    /// The type of token manager to deploy
    pub token_manager_type: Uint256,
    /// The address of the token on the destination chain
    pub destination_token_address: nonempty::HexBinary,
    /// The parameters to be provided to the token manager contract
    pub params: Option<nonempty::HexBinary>,
}

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    /// Register XRPL token metadata for custom token linking.
    #[permission(Elevated)]
    RegisterTokenMetadata { xrpl_token: XRPLTokenOrXrp },

    /// Register an XRPL token as an interchain token.
    #[permission(Elevated)]
    RegisterLocalToken {
        xrpl_token: XRPLToken,
    },

    /// Register a remote token on the XRPL chain,
    /// defining its XRPL currency.
    #[permission(Elevated)]
    RegisterRemoteToken {
        token_id: TokenId,
        #[serde(with = "xrpl_currency_string")]
        #[schemars(with = "String")]
        xrpl_currency: XRPLCurrency,
    },

    /// Register a remote token that is deployed on another chain.
    #[permission(Elevated)]
    RegisterTokenInstance {
        token_id: TokenId,
        chain: ChainNameRaw,
        decimals: u8,
    },

    /// Deploy a token manager on some destination chain.
    #[permission(Elevated)]
    LinkToken {
        token_id: TokenId,
        destination_chain: ChainNameRaw,
        link_token: LinkToken,
    },

    /// Deploy a token on some destination chain.
    #[permission(Elevated)]
    DeployRemoteToken {
        xrpl_token: XRPLTokenOrXrp,
        destination_chain: ChainNameRaw,
        token_metadata: TokenMetadata,
    },

    /// Before messages that are unknown to the system can be routed, they need to be verified.
    /// Use this call to trigger verification for any of the given messages that is still unverified.
    #[permission(Any)]
    VerifyMessages(Vec<XRPLMessage>),

    /// Forward the given outgoing messages (coming to XRPL) to the next step of the routing layer.
    /// NOTE: In XRPL, this is only used to route outgoing messages, therefore they are already verified.
    /// NOTE: Should be named RouteOutgoingMessages, but we keep the name for compatibility with the router.
    #[permission(Specific(router))]
    RouteMessages(Vec<Message>),

    /// Forward the given incoming messages (coming from XRPL) to the next step of the routing layer.
    /// They are reported by the relayer and need verification.
    #[permission(Any)]
    RouteIncomingMessages(Vec<WithPayload<XRPLMessage>>),

    /// Confirm verified gas top-up messages.
    #[permission(Any)]
    ConfirmAddGasMessages(Vec<XRPLAddGasMessage>),

    #[permission(Governance)]
    UpdateAdmin { new_admin_address: String },
}

#[cw_serde]
pub struct MessageWithPayload {
    pub message: Message,
    pub payload: nonempty::HexBinary,
}

#[cw_serde]
pub struct InterchainTransfer {
    // When the amount is zero, route_incoming_messages is a no-op.
    pub message_with_payload: Option<MessageWithPayload>,
    pub token_id: TokenId,
    pub dust: XRPLPaymentAmount,
}

#[cw_serde]
pub struct CallContract {
    pub message_with_payload: MessageWithPayload,
    pub gas_token_id: TokenId,
}

#[cw_serde]
#[derive(QueryResponses)]
#[allow(clippy::large_enum_variant)]
pub enum QueryMsg {
    // messages that can be relayed to the chain corresponding to this gateway
    #[returns(Vec<Message>)]
    OutgoingMessages(Vec<CrossChainId>),

    #[returns(XRPLToken)]
    XrplToken(TokenId),

    #[returns(TokenId)]
    XrplTokenId(XRPLToken),

    #[returns(TokenId)]
    XrpTokenId,

    #[returns(TokenId)]
    LinkedTokenId(XRPLToken),

    #[returns(u8)]
    TokenInstanceDecimals {
        chain_name: ChainNameRaw,
        token_id: TokenId,
    },

    #[returns(InterchainTransfer)]
    InterchainTransfer {
        message: XRPLInterchainTransferMessage,
        payload: Option<nonempty::HexBinary>,
    },

    #[returns(CallContract)]
    CallContract {
        message: XRPLCallContractMessage,
        payload: nonempty::HexBinary,
    },
}
