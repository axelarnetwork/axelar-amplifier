use axelar_wasm_std::permission_control::Permission;
use itertools::Itertools;
use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::punctuated::Punctuated;
use syn::token::Comma;
use syn::{Data, DataEnum, DeriveInput, Expr, ExprCall, Ident, Path, Token, Variant};

/// This macro derives the `ensure_permissions` method for an enum. The method checks if the sender
/// has the required permissions to execute the variant. The permissions are defined using the
/// `#[permission]` attribute. The attribute can be used in two ways:
/// - `#[permission(Permission1, Permission2, ...)]` requires the sender to have at least one of
///     the specified permissions. These permissions are defined in the [axelar_wasm_std::permission_control::Permission] enum.
/// - `#[permission(Specific(Addr1, Addr2, ...))]` requires the sender to be one of the specified
///     addresses. The macro will generate a function signature that takes closures as arguments to determine
///     the whitelisted addresses.
///
/// Both attributes can be used together, in which case the sender must have at least one of the
/// specified permissions or be one of the specified addresses.
/// The `ensure_permissions` method will return an error if the sender does not have the required
/// permissions.
///
/// # Example
/// ```
/// use cosmwasm_std::{Addr, Deps, Env, MessageInfo};
/// use axelar_wasm_std::permission_control::Permission;
/// use msgs_derive::EnsurePermissions;
///
/// #[derive(EnsurePermissions)]
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
/// #         Ok(Addr::unchecked("gateway"))
/// #     }
/// # }
/// # const GATEWAY:Store = Store;
/// # use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
/// # fn main() {
/// # let mocks = mock_dependencies();
/// # let deps = mocks.as_ref();
/// # let env = mock_env();
/// // example how to call the execute function
/// let info = MessageInfo{
///    sender: Addr::unchecked("sender"),
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

#[proc_macro_derive(EnsurePermissions, attributes(permission))]
pub fn derive_ensure_permissions(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let ident = input.ident.clone();

    match input.data.clone() {
        Data::Enum(data) => build_implementation(ident, data),
        _ => panic!("Only enums are supported"),
    }
}
fn build_implementation(enum_type: Ident, data: DataEnum) -> TokenStream {
    let (variants, permissions): (Vec<_>, Vec<_>) = data
        .variants
        .into_iter()
        .filter_map(find_permissions)
        .unzip();

    let specific_check = build_specific_permissions_check(&enum_type, &variants, &permissions);
    let general_check = build_general_permissions_check(&enum_type, &variants, &permissions);
    let check_function = build_full_check_function(&permissions, specific_check, general_check);

    TokenStream::from(quote! {
        impl #enum_type{
            #check_function
        }
    })
}

#[derive(Debug)]
struct MsgPermissions {
    specific: Vec<Path>,
    general: Vec<Path>,
}

fn find_permissions(variant: Variant) -> Option<(Ident, MsgPermissions)> {
    let (specific, general): (Vec<_>, Vec<_>) = variant
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
            Expr::Path(path) => (None, Some(path.path)),
            Expr::Call(ExprCall { args, func, .. }) => {
                let paths = parse_specific_permissions(&variant, args);
                if !is_specific_attribute(&func) {
                    panic!(
                        "unrecognized permission attribute for variant {}, suggestion: 'Specific(...)'?",
                        variant.ident
                    );
                }
                (Some(paths), None)
            }
            expr =>
                panic!(
                    "unrecognized permission attribute '{}' for variant {}",
                    quote! {#expr}, variant.ident
                )
        })
        .unzip();

    let specific: Vec<Path> = specific.into_iter().flatten().flatten().collect();
    let general: Vec<Path> = general.into_iter().flatten().collect();

    if !general.iter().all_unique() {
        panic!("permissions for variant {} must be unique", variant.ident);
    }

    if !specific.iter().all_unique() {
        panic!(
            "whitelisted addresses for variant {} must be unique",
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

    Some((variant.ident, MsgPermissions { specific, general }))
}

fn is_specific_attribute(func: &Expr) -> bool {
    match func {
        Expr::Path(path) => path.path.is_ident("Specific"),
        _ => false,
    }
}

fn parse_specific_permissions(
    variant: &Variant,
    args: Punctuated<Expr, Comma>,
) -> impl IntoIterator<Item = Path> + '_ {
    args.into_iter().map(|arg| match arg {
        Expr::Path(path) => path.path,
        _ => panic!("wrong format of 'Specific' permission attribute for variant {}, only comma separated identifiers are allowed", variant.ident),
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

fn build_full_check_function(
    permissions: &[MsgPermissions],
    specific_permission_body: proc_macro2::TokenStream,
    general_permission_body: proc_macro2::TokenStream,
) -> proc_macro2::TokenStream {
    let unique_specific_permissions = permissions
        .iter()
        .flat_map(|permission| permission.specific.iter())
        .unique()
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
