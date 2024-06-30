use axelar_wasm_std::permission_control::Permission;
use itertools::Itertools;
use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::punctuated::Punctuated;
use syn::token::Comma;
use syn::{Data, DataEnum, DeriveInput, Expr, ExprCall, Ident, Path, Token, Variant};

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
        .filter_map(|attr| attr.parse_args_with(Punctuated::parse_terminated).ok())
        .flat_map(|expr: Punctuated<Expr, Token![,]>| expr)
        .map(|expr| match expr {
            Expr::Path(path) => (None, Some(path.path)),
            Expr::Call(ExprCall { args, func, .. }) if is_specific_attribute(&func) => {
                let paths = parse_specific_permissions(&variant, args);
                (Some(paths), None)
            }
            _ => panic!(
                "unrecognized permission attribute for variant {}",
                variant.ident
            ),
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
            quote! {();}
        } else {
            quote! {
                #(
                    let stored_addr = error_stack::ResultExt::change_context(
                        #specific_permissions(storage).map_err(|err| error_stack::Report::from(err)),
                        axelar_wasm_std::permission_control::Error::WhitelistNotFound{sender: sender.clone()})?;
                    if sender == stored_addr {
                        return Ok(self);
                    }
                    whitelisted.push(stored_addr);
                )*
            }
        }
    });

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
            quote! {
                return Err(axelar_wasm_std::permission_control::Error::AddressNotWhitelisted {
                    expected: whitelisted.clone(),
                    actual: sender.clone(),
                }.into())
            }
        } else {
            quote! {(#(axelar_wasm_std::permission_control::Permission::#general_permissions )|*).into()}
        }
    });

    quote! {
        let permission : axelar_wasm_std::flagset::FlagSet<_> = match self {
            #(#enum_type::#variants {..}=> {#general_permissions_quote})*
        };

        if !permission.contains(axelar_wasm_std::permission_control::Permission::Any) {
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

    if unique_specific_permissions.is_empty() {
        quote! {
            pub fn ensure_permissions(self, storage: &dyn cosmwasm_std::Storage, sender: &cosmwasm_std::Addr)
                -> error_stack::Result<Self, axelar_wasm_std::permission_control::Error> {

                #general_permission_body
            }
        }
    } else {
        let fs: Vec<_> = (0..unique_specific_permissions.len())
            .map(|i| format_ident!("F{}", i))
            .collect();

        let cs: Vec<_> = (0..unique_specific_permissions.len())
            .map(|i| format_ident!("C{}", i))
            .collect();

        quote! {
            pub fn ensure_permissions<#(#fs),*, #(#cs),*>(
                self,
                storage: &dyn cosmwasm_std::Storage,
                sender: &cosmwasm_std::Addr,
                #(#unique_specific_permissions: #fs),*)
                -> error_stack::Result<Self,axelar_wasm_std::permission_control::Error>
                    where
                        #(#fs:FnOnce(&dyn cosmwasm_std::Storage) -> error_stack::Result<cosmwasm_std::Addr, #cs>),*,
                        #(#cs: error_stack::Context),*
                    {
                #specific_permission_body

                #general_permission_body
            }
        }
    }
}
