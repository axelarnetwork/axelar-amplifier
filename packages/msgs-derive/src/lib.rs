use std::cmp::Ordering;
use std::collections::HashMap;

use axelar_wasm_std::permission_control::Permission;
use itertools::Itertools;
use proc_macro::TokenStream;
use proc_macro2::{Literal, Span};
use quote::{format_ident, quote, ToTokens};
use serde_json::json;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::token::Comma;
use syn::{parse_quote, Expr, ExprCall, Ident, ItemEnum, ItemFn, Path, Token, Variant};

/// This macro derives the `ensure_permissions` method for an enum. The method checks if the sender
/// has the required permissions to execute the variant. The permissions are defined using the
/// `#[permission]` attribute. The attribute can be used in two ways:
/// - `#[permission(Permission1, Permission2, ...)]` requires the sender to have at least one of
///   the specified permissions. These permissions are defined in the [axelar_wasm_std::permission_control::Permission] enum.
/// - `#[permission(Specific(Addr1, Addr2, ...))]` requires the sender to be one of the specified
///   addresses. The macro will generate a function signature that takes closures as arguments to determine
///   the whitelisted addresses.
///
/// Both attributes can be used together, in which case the sender must have at least one of the
/// specified permissions or be one of the specified addresses.
/// The `ensure_permissions` method will return an error if the sender does not have the required
/// permissions.
///
/// # Example
/// ```
/// use cosmwasm_schema::cw_serde;
/// use cosmwasm_std::{Addr, Deps, Env, MessageInfo};
/// use cosmwasm_std::testing::MockApi;
/// use axelar_wasm_std::permission_control::Permission;
/// use msgs_derive::Permissions;
///
/// #[cw_serde]
/// #[derive(Permissions)]
/// pub enum ExecuteMsg {
///     #[permission(NoPrivilege, Admin)]
///     AnyoneButGovernanceCanCallThis,
///     #[permission(Governance)]
///     OnlyGovernanceCanCallThis,
///     #[permission(Admin, Specific(gateway))]
///     AdminOrGatewayCanCallThis,
///     #[permission(Specific(gateway))]
///     OnlyGatewayCanCallThis
/// }
///
/// fn execute(deps: Deps, env: Env, info: MessageInfo, msg: ExecuteMsg) -> error_stack::Result<(), axelar_wasm_std::permission_control::Error> {
///     // check permissions before handling the message
///     match msg.ensure_permissions(deps.storage, &info.sender, |storage, message | GATEWAY.load(storage))? {
///         ExecuteMsg::AnyoneButGovernanceCanCallThis => Ok(()),
///         ExecuteMsg::OnlyGovernanceCanCallThis => Ok(()),
///         ExecuteMsg::AdminOrGatewayCanCallThis => Ok(()),
///         ExecuteMsg::OnlyGatewayCanCallThis => Ok(()),
///     }
/// }
///
/// # // mock to make the example compile
/// # struct Store;
/// # impl Store {
/// #     fn load(&self, storage: &dyn cosmwasm_std::Storage) -> error_stack::Result<Addr, axelar_wasm_std::permission_control::Error> {
/// #         Ok(MockApi::default().addr_make("gateway"))
/// #     }
/// # }
/// # const GATEWAY: Store = Store;
/// # use cosmwasm_std::testing::{mock_dependencies, mock_env, message_info};
/// # fn main() {
/// # let mocks = mock_dependencies();
/// # let deps = mocks.as_ref();
/// # let env = mock_env();
/// // example how to call the execute function
/// let info = MessageInfo{
///    sender: MockApi::default().addr_make("sender"),
///    funds: vec![],
/// };
///
/// # let info_root = info;
/// # let info = info_root.clone();
/// assert!(execute(deps, env, info, ExecuteMsg::AnyoneButGovernanceCanCallThis).is_ok());
/// # let env = mock_env();
/// # let info = info_root.clone();
/// assert!(execute(deps, env, info, ExecuteMsg::OnlyGatewayCanCallThis).is_err());
/// # }
/// ```
#[proc_macro_derive(Permissions, attributes(permission))]
pub fn derive_ensure_permissions(input: TokenStream) -> TokenStream {
    // This will trigger a compile time error if the parse failed. In other words,
    // this macro can only be used on an enum.
    let data = syn::parse_macro_input!(input as ItemEnum);
    let ident = data.ident.clone();

    build_implementation(ident, data)
}

fn build_implementation(enum_type: Ident, data: ItemEnum) -> TokenStream {
    let (variants, permissions): (Vec<_>, Vec<_>) = data
        .variants
        .clone()
        .into_iter()
        .filter_map(find_permissions)
        .unzip();

    let external_execute_msg_ident = external_execute_msg_ident(enum_type.clone());
    let visibility = data.vis.clone();

    let specific_check = build_specific_permissions_check(&enum_type, &variants, &permissions);
    let general_check = build_general_permissions_check(&enum_type, &variants, &permissions);
    let check_function = build_full_check_function(&permissions, specific_check, general_check);
    let verify_external_executors =
        build_verify_external_executor_function(&enum_type, &variants, &permissions);
    let golden_test = build_golden_test(&enum_type, &variants, &permissions);

    TokenStream::from(quote! {
        #[cw_serde]
        #visibility enum #external_execute_msg_ident {
            Relay {
                original_sender: cosmwasm_std::Addr,
                msg: #enum_type,
            },

            #[serde(untagged)]
            Direct(#enum_type),
        }

        impl #enum_type{
            #check_function
        }

        impl From<#enum_type> for #external_execute_msg_ident {
            fn from(msg: #enum_type) -> #external_execute_msg_ident {
                #external_execute_msg_ident::Direct(msg)
            }
        }

        impl client::MsgFromProxy for #enum_type{
            type MsgWithOriginalSender = #external_execute_msg_ident;

            fn via_proxy(
                self,
                original_sender: cosmwasm_std::Addr,
            ) -> Self::MsgWithOriginalSender {
                #external_execute_msg_ident::Relay {
                    original_sender,
                    msg: self,
                }
            }
        }

        impl #external_execute_msg_ident {
            #verify_external_executors
        }

        #golden_test
    })
}

#[derive(Debug)]
struct MsgPermissions {
    specific: Vec<Path>,
    general: Vec<Path>,
    external: Vec<Path>,
}

fn find_permissions(variant: Variant) -> Option<(Ident, MsgPermissions)> {
    let (specific, general, external): (Vec<_>, Vec<_>, Vec<_>) = variant
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("permission"))
        .flat_map(|attr|
        {
            match attr.
                parse_args_with(Punctuated::<Expr, Token![,]>::parse_terminated){
                Ok(expr) => expr,
                _=> panic!("wrong format of 'permission' attribute for variant {}", variant.ident)
            }
        })
        .map(|expr| match expr {
            Expr::Path(path) => (None, Some(path.path), None),
            Expr::Call(ExprCall { args, func, .. }) => {
                let paths = parse_non_general_permissions(&variant, args);

                match *func {
                    Expr::Path(p) if p.path.is_ident("Specific") => {
                        (Some(paths), None, None)
                    },
                    Expr::Path(p) if p.path.is_ident("Proxy") => {
                        (None, None, Some(paths))
                    },
                    _ => panic!(
                        "unrecognized permission attribute for variant {}, suggestion: 'Specific(...)' or 'Proxy(...)'?",
                        variant.ident
                    ),
                }
            }
            expr =>
                panic!(
                    "unrecognized permission attribute '{}' for variant {}",
                    quote! {#expr}, variant.ident
                )
        })
        .multiunzip();

    let specific: Vec<Path> = specific.into_iter().flatten().flatten().collect();
    let general: Vec<Path> = general.into_iter().flatten().collect();
    let external: Vec<Path> = external.into_iter().flatten().flatten().collect();

    if !general.iter().all_unique() {
        panic!("permissions for variant {} must be unique", variant.ident);
    }

    if !specific.iter().all_unique() {
        panic!(
            "whitelisted addresses for variant {} must be unique",
            variant.ident
        );
    }

    if !external.iter().all_unique() {
        panic!(
            "whitelisted external addresses for variant {} must be unique",
            variant.ident
        );
    }

    if general.is_empty() && specific.is_empty() {
        panic!(
            "permissions for variant {} must not be empty",
            variant.ident
        );
    }

    if general.iter().any(is_permission_any) && !specific.is_empty() {
        panic!(
            "whitelisting addresses for variant {} is useless because permission '{:?}' is set",
            variant.ident,
            Permission::Any
        );
    }

    Some((
        variant.ident,
        MsgPermissions {
            specific,
            general,
            external,
        },
    ))
}

fn parse_non_general_permissions(
    variant: &Variant,
    args: Punctuated<Expr, Comma>,
) -> impl IntoIterator<Item = Path> + '_ {
    args.into_iter().map(|arg| match arg {
        Expr::Path(path) => path.path,
        _ => panic!("wrong format of non-general permission attribute for variant {}, only comma separated identifiers are allowed", variant.ident),
    })
}

fn is_permission_any(path: &Path) -> bool {
    path.get_ident()
        .filter(|ident| ident.to_string() == format!("{:?}", Permission::Any))
        .is_some()
}

fn build_specific_permissions_check(
    enum_type: &Ident,
    variants: &[Ident],
    permissions: &[MsgPermissions],
) -> proc_macro2::TokenStream {
    let specific_permissions = permissions.iter().map(|permission| {
        let specific_permissions: &[_] = permission.specific.as_ref();

        if permission.specific.is_empty() {
            // don't do anything if there are no specific permissions
            quote! {();}
        } else {
            // load all whitelisted addresses from storage and check if the sender is whitelisted
            quote! {
                #(
                    let stored_addr = error_stack::ResultExt::change_context(
                        #specific_permissions(storage, &self).map_err(|err| error_stack::Report::from(err)),
                        axelar_wasm_std::permission_control::Error::WhitelistNotFound{sender: sender.clone()})?;
                    if sender == stored_addr {
                        return Ok(self);
                    }
                    whitelisted.push(stored_addr);
                )*
            }
        }
    });

    // map enum variants to specific permission checks
    quote! {
        let mut whitelisted = Vec::new();
        match self {
            #(#enum_type::#variants {..}=> {#specific_permissions})*
        };
    }
}

fn build_general_permissions_check(
    enum_type: &Ident,
    variants: &[Ident],
    permissions: &[MsgPermissions],
) -> proc_macro2::TokenStream {
    let general_permissions_quote = permissions.iter().map(|permission| {
        let general_permissions: &[_] = permission.general.as_ref();

        if general_permissions.is_empty() && !permission.specific.is_empty() {
            // getting to this point means the specific check has failed, so we return an error
            quote! {
                Err(axelar_wasm_std::permission_control::Error::AddressNotWhitelisted {
                    expected: whitelisted.clone(),
                    actual: sender.clone(),
                }.into())
            }
        } else {
            // specific permissions have either failed or there were none, so check general permissions
            quote! {Ok((#(axelar_wasm_std::permission_control::Permission::#general_permissions )|*).into())}
        }
    });

    // map enum variants to general permission checks. Exclude checks for the 'Any' case,
    // because it allows any address, compare permissions to the sender's role otherwise.
    quote! {
        let permission : Result<axelar_wasm_std::flagset::FlagSet<_>, axelar_wasm_std::permission_control::Error > = match self {
            #(#enum_type::#variants {..}=> {#general_permissions_quote})*
        };

        let permission = permission?;

        if permission.contains(axelar_wasm_std::permission_control::Permission::Any) {
            return Ok(self);
        }

        let role = error_stack::ResultExt::change_context(
            axelar_wasm_std::permission_control::sender_role(storage, sender),
            axelar_wasm_std::permission_control::Error::PermissionDenied {
                expected: permission.clone(),
                actual: axelar_wasm_std::permission_control::Permission::NoPrivilege.into(),
            },
        )?;

        if (*permission & *role).is_empty() {
            return Err(axelar_wasm_std::permission_control::Error::PermissionDenied {
                expected: permission,
                actual: role,
            }
            .into());
        }

        Ok(self)
    }
}

fn build_verify_external_executor_function(
    enum_type: &Ident,
    variants: &[Ident],
    permissions: &[MsgPermissions],
) -> proc_macro2::TokenStream {
    let ensure_contract_has_permission = permissions.iter().map(|permission| {
        let allowed_contracts: Vec<_> = permission
            .external
            .iter()
            .map(|path| {
                syn::LitStr::new(
                    &path
                        .get_ident()
                        .expect("error parsing proxy contract's name from permissions")
                        .to_string(),
                    Span::call_site(),
                )
            })
            .collect();

        quote! {
            #(
                if contract_name == #allowed_contracts {
                    return Ok(msg);
                }
            )*
            error_stack::bail!(axelar_wasm_std::permission_control::Error::Unauthorized)
        }
    });

    quote! {
        pub fn verify_external_executor(
            msg: #enum_type,
            contract_name: String,
        ) -> error_stack::Result<#enum_type, axelar_wasm_std::permission_control::Error> {
            match msg {
                #(#enum_type::#variants {..} => {#ensure_contract_has_permission}),*
                _ => error_stack::bail!(axelar_wasm_std::permission_control::Error::Unauthorized),
            }
        }
    }
}

fn build_full_check_function(
    permissions: &[MsgPermissions],
    specific_permission_body: proc_macro2::TokenStream,
    general_permission_body: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    let unique_specific_permissions = permissions
        .iter()
        .flat_map(|permission| permission.specific.iter())
        .unique()
        .sorted_by(|a, b| {
            sort_permissions(
                a.get_ident()
                    .expect("error parsing specific permission identifier"),
                b.get_ident()
                    .expect("error parsing specific permission identifier"),
            )
        })
        .collect::<Vec<_>>();

    let comments = quote! {
        /// Ensure the annotated permissions are met by the sender.
        /// If the sender does not have the required permissions, an error is returned.
    };

    // the function signature is different depending on how many specific permissions are defined
    if unique_specific_permissions.is_empty() {
        quote! {
            #comments
            /// # Arguments
            /// * `storage` - The storage to load the sender's role from.
            /// * `sender` - The sender's address to check for whitelisting.
            pub fn ensure_permissions(self, storage: &dyn cosmwasm_std::Storage, sender: &cosmwasm_std::Addr)
                -> error_stack::Result<Self, axelar_wasm_std::permission_control::Error> {

                #general_permission_body
            }
        }
    } else {
        // due to how rust handles closures, the easiest way to define functions as parameters is with independent generic types,
        // one function with one return value for each specific permission
        let fs: Vec<_> = (0..unique_specific_permissions.len())
            .map(|i| format_ident!("F{}", i))
            .collect();

        let cs: Vec<_> = (0..unique_specific_permissions.len())
            .map(|i| format_ident!("C{}", i))
            .collect();

        let args = quote!(#(#unique_specific_permissions),*);
        let format = format!(
            "* `{}` - The function(s) to load whitelisted addresses from storage.",
            args
        );
        quote! {
            #comments
            /// # Arguments
            /// * `storage` - The storage to load the whitelisted addresses and the sender's role from.
            /// * `sender` - The sender's address to check for whitelisting.
            #[doc = #format]
            pub fn ensure_permissions<#(#fs),*, #(#cs),*>(
                self,
                storage: &dyn cosmwasm_std::Storage,
                sender: &cosmwasm_std::Addr,
                #(#unique_specific_permissions: #fs),*)
                -> error_stack::Result<Self,axelar_wasm_std::permission_control::Error>
                    where
                        #(#fs:FnOnce(&dyn cosmwasm_std::Storage, &Self) -> error_stack::Result<cosmwasm_std::Addr, #cs>),*,
                        #(#cs: error_stack::Context),*
                    {
                #specific_permission_body

                #general_permission_body
            }
        }
    }
}

fn sort_permissions(p1: &Ident, p2: &Ident) -> Ordering {
    p1.to_string().cmp(&p2.to_string())
}

fn external_execute_msg_ident(execute_msg_ident: Ident) -> Ident {
    format_ident!("{}FromProxy", execute_msg_ident.clone())
}

/// AllPermissions is a custom struct used to parse the attributes for the external_execute macro
/// The external_execute macro must be defined as follows:
///
/// #[external_execute(proxy(coordinator = find_coordinator_address), direct(verifier = find_varifier_address))]
///
/// ContractPermission is a vector of tuples, where the first element is the contract name, and the second
/// is the authorization function.
///
/// The aforementioned example denotes that the 'find_coordinator' function will be used to authorize
/// the coordinator contract, and the 'find_verifier' function is used to authorize the verifier contract.
/// The authorization function is the same as is provided to the ensure_permissions method, and it's
/// signature is as follows:
///
/// FnOnce(&dyn cosmwasm_std::Storage, &ExecuteMsg) -> error_stack::Result<cosmwasm_std::Addr, impl error_stack::Context>
///
/// The authorized address is returned.
///
/// proxy: Proxy contracts that are allowed to execute messages on this contract.
/// direct: Addresses that are allowed to execute particular messages.
#[derive(Debug)]
struct ContractPermission(Vec<(Ident, Expr)>);

impl IntoIterator for ContractPermission {
    type Item = (Ident, Expr);
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[derive(Debug)]
struct AllPermissions {
    relay_permissions: ContractPermission,
    specific_permissions: ContractPermission,
}

impl Parse for AllPermissions {
    fn parse(input: ParseStream) -> Result<Self, syn::Error> {
        let punct = Punctuated::<ExprCall, Token![,]>::parse_terminated(input)?;
        let parse_permissions_list = |expr_call: ExprCall,
                                      expected_call_name: String|
         -> Option<Vec<(Ident, Expr)>> {
            let mut contracts_seen: HashMap<String, ()> = HashMap::new();

            match *expr_call.func {
                Expr::Path(path) => {
                    match path.path.get_ident() {
                        Some(path_ident) => {
                            if path_ident
                                .eq(&Ident::new(expected_call_name.as_str(), Span::call_site()))
                            {
                                // Permission functions for checking contract addresses
                                Some(expr_call.args
                                    .into_iter()
                                    .filter_map(|arg| match arg {
                                        Expr::Assign(a) => {
                                            let Expr::Path(contract_name) = *a.left else {
                                                return None;
                                            };

                                            let contract_ident = contract_name.path.get_ident()?;
                                            match contracts_seen.insert(contract_ident.to_string().clone(), ()) {
                                                Some(_) => panic!("every identifier must appear at most once (left hand side of assignment)"),
                                                None => Some((contract_ident.clone(), *a.right)),
                                            }
                                        },
                                        _ => panic!("expected format 'contract == contract_permission_fn'"),
                                    })
                                    .collect::<Vec<(Ident, Expr)>>()
                                )
                            } else {
                                None
                            }
                        }
                        None => None,
                    }
                }
                _ => panic!("expecting call to be a path name"),
            }
        };

        Ok(AllPermissions {
            relay_permissions: ContractPermission(
                punct
                    .iter()
                    .filter_map(|e| parse_permissions_list(e.clone(), String::from("proxy")))
                    .flatten()
                    .collect(),
            ),
            specific_permissions: ContractPermission(
                punct
                    .iter()
                    .filter_map(|e| parse_permissions_list(e.clone(), String::from("direct")))
                    .flatten()
                    .collect(),
            ),
        })
    }
}

fn validate_external_contract_with_args(
    contracts: Vec<Ident>,
    contract_names: Vec<Ident>,
    fs: Vec<Ident>,
    cs: Vec<Ident>,
) -> TokenStream {
    TokenStream::from(quote! {
        // this function can be called with a lot of arguments, so we suppress the warning
        #[allow(clippy::too_many_arguments)]
        fn validate_external_contract<#(#fs),*, #(#cs),*>(
                storage: &dyn cosmwasm_std::Storage,
                contract_addr: Addr,
                #(#contracts: #fs),*,
                #(#contract_names: String),*
            ) -> error_stack::Result<String, axelar_wasm_std::permission_control::Error>
            where
            #(#fs:FnOnce(&dyn cosmwasm_std::Storage) -> error_stack::Result<cosmwasm_std::Addr, #cs>),*,
            #(#cs: error_stack::Context),*
                {
                #(
                    match #contracts(storage) {
                        Ok(stored_addr) => {
                            if stored_addr == contract_addr {
                                return Ok(#contract_names);
                            }
                        },
                        Err(_) => {},
                    }
                )*

            Err(error_stack::report!(axelar_wasm_std::permission_control::Error::Unauthorized))
        }
    })
}

fn validate_external_contract_no_args() -> TokenStream {
    TokenStream::from(quote! {
        fn validate_external_contract(
                storage: &dyn cosmwasm_std::Storage,
                contract_addr: Addr,
            ) -> error_stack::Result<String, axelar_wasm_std::permission_control::Error>
                {
            // This is only called when a relay message is executed. Since no proxy contract has
            // permission to execute a message, this will always be an error.
            Err(error_stack::report!(axelar_wasm_std::permission_control::Error::Unauthorized))
        }
    })
}

fn validate_external_contract_function(contracts: Vec<Ident>) -> TokenStream {
    if !contracts.is_empty() {
        let fs: Vec<_> = (0..contracts.len())
            .map(|i| format_ident!("F{}", i))
            .collect();

        let cs: Vec<_> = (0..contracts.len())
            .map(|i| format_ident!("C{}", i))
            .collect();

        let contract_names: Vec<_> = contracts
            .iter()
            .map(|c| {
                let mut new_arg = c.to_string().clone();
                new_arg.push_str("_str");
                Ident::new(new_arg.as_str(), Span::call_site())
            })
            .collect();

        validate_external_contract_with_args(contracts, contract_names, fs, cs)
    } else {
        validate_external_contract_no_args()
    }
}

/// This macro enforces two requirements:
///
/// 1. If a proxy contract wants to execute a message on this contract, that proxy contract
///    must have permission to do so.
/// 2. The original sender of a message has permission to execute that message. If the message
///    is sent by a proxy contract, the original sender is the address that initiated the transaction
///    on the proxy.
///
/// This macro takes arguments of the form:
///
/// #\[external_execute(proxy(contract = find_contract_address), direct(sender = find_sender_address))\]
///
/// 'proxy' handles case 1, and 'direct' handles
/// case 2. In both scenarios, the left hand side of the assignment is the identifier for the
/// contract and original sender, respectively. The right hand side is a function with the signature:
///
/// FnOnce(&dyn cosmwasm_std::Storage) -> error_stack::Result<cosmwasm_std::Addr, impl error_stack::Context>
///
/// for contracts, and
///
/// FnOnce(&dyn cosmwasm_std::Storage, &ExecuteMsg) -> error_stack::Result<cosmwasm_std::Addr, impl error_stack::Context>
///
/// for addresses. The right hand side can be an expression that returns a function with that signature.
#[proc_macro_attribute]
pub fn ensure_permissions(attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut execute_fn = syn::parse_macro_input!(item as ItemFn);
    if execute_fn.sig.ident != format_ident!("execute") {
        panic!("ensure_permissions macro can only be used with execute endpoint")
    }

    let all_permissions = syn::parse_macro_input!(attr as AllPermissions);
    let (contract_names, contract_permissions): (Vec<_>, Vec<_>) =
        all_permissions.relay_permissions.into_iter().unzip();
    let (_, specific_permissions): (Vec<_>, Vec<_>) = all_permissions
        .specific_permissions
        .into_iter()
        .sorted_by(|a, b| sort_permissions(&a.0, &b.0))
        .unzip();

    let contract_names_literals: Vec<_> = contract_names
        .iter()
        .map(|cn| Literal::string(cn.to_string().as_str()))
        .collect();

    // Replace ExecuteMsg with ExecuteMsgFromProxy
    let original_msg = execute_fn
        .sig
        .inputs
        .pop()
        .expect("error parsing execute endpoint's last argument")
        .into_value();
    let original_msg_ident = match original_msg {
        syn::FnArg::Typed(typ) => match *typ.ty {
            syn::Type::Path(p) => p
                .path
                .get_ident()
                .expect("error parsing execute message type")
                .clone(),
            _ => panic!("problem parsing final argument of 'execute'"),
        },
        _ => panic!("last argument of 'execute' must be a typed execute message"),
    };
    let new_msg_ident = external_execute_msg_ident(original_msg_ident.clone());

    execute_fn
        .sig
        .inputs
        .push(parse_quote! {msg: #new_msg_ident});

    let validate_fn = validate_external_contract_function(contract_names.clone());
    let validate_fn = syn::parse_macro_input!(validate_fn as ItemFn);

    let validate_external_contract_call = if contract_permissions.is_empty() {
        quote!(validate_external_contract(
            deps.storage,
            info.sender.clone()
        )?)
    } else {
        quote!(
            validate_external_contract(
                deps.storage,
                info.sender.clone(),
                #(#contract_permissions),*,
                #(#contract_names_literals.to_string()),*
            )?
        )
    };

    let statements = execute_fn.block.stmts;
    execute_fn.block = parse_quote!(
        {
            let (msg, info) = match msg.into() {
                #new_msg_ident::Relay{original_sender, msg} => {
                    // Validate that the sending contract is allowed to execute messages.
                    (#new_msg_ident::verify_external_executor(
                        msg,
                        #validate_external_contract_call,
                    )?, cosmwasm_std::MessageInfo {
                        sender: original_sender,
                        funds: info.funds,
                    })
                },
                #new_msg_ident::Direct(msg) => {
                    (msg, info)
                },
            };

            // Ensure permissions
            let msg = msg.ensure_permissions(
                deps.storage,
                &info.sender,
                #(#specific_permissions),*
            )?;

            // Perform authorization and execution for original sender and message
            #(#statements)*
        }
    );

    TokenStream::from(quote! {
        #execute_fn

        #validate_fn
    })
}

fn build_golden_test(
    enum_type: &Ident,
    variants: &[Ident],
    permissions: &[MsgPermissions],
) -> proc_macro2::TokenStream {
    let test_name = format_ident!(
        "{}_permissions_should_not_change",
        enum_type.to_string().to_lowercase()
    );
    let module_name = format_ident!(
        "{}_permissions_golden_test",
        enum_type.to_string().to_lowercase()
    );

    let permissions_jsons = permissions.iter().map(
        |MsgPermissions {
             specific,
             general,
             external,
         }| {
            let specific = specific
                .iter()
                .map(|p| p.to_token_stream().to_string())
                .collect::<Vec<_>>();
            let general = general
                .iter()
                .map(|p| p.to_token_stream().to_string())
                .collect::<Vec<_>>();
            let external = external
                .iter()
                .map(|p| p.to_token_stream().to_string())
                .collect::<Vec<_>>();

            json!({
                "specific": specific,
                "general": general,
                "external": external
            })
        },
    );

    let permissions_map = variants
        .iter()
        .map(|variant| variant.to_string())
        .zip(permissions_jsons)
        .collect::<HashMap<_, _>>();

    let permissions_json = serde_json::to_string_pretty(&permissions_map)
        .expect("error serializing permissions map to JSON");

    quote! {
        #[cfg(test)]
        mod #module_name {
            use super::*;

            #[test]
            fn #test_name() {
                goldie::assert!(#permissions_json);
            }
        }
    }
}
