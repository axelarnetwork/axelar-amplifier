use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Variant};

#[proc_macro_derive(EnsurePermissions, attributes(permission))]
pub fn derive_ensure_permissions(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let ident = input.ident.clone();

    match input.data.clone() {
        Data::Enum(data) => {
            let (variants, permissions): (Vec<_>, Vec<_>) = data
                .variants
                .iter()
                .filter_map(|variant| {
                    find_permission(variant).map(|permission| (variant.ident.clone(), permission))
                })
                .unzip();

            TokenStream::from(quote! {
                use axelar_wasm_std::permission_control as _permission_control;
                use cosmwasm_std::Storage as _Storage;
                use cosmwasm_std::Addr as _Addr;
                use axelar_wasm_std as _axelar_wasm_std;
                use error_stack as _error_stack;

                impl #ident  {
                    pub fn ensure_permission(self, storage: &dyn _Storage, sender: &_Addr) -> Result<Self, _error_stack::Report<_permission_control::Error>> {
                        let permission = match self {
                            #(#ident::#variants {..}=> {_permission_control::Permission::#permissions})*
                        };

                        let permission = _axelar_wasm_std::flagset::FlagSet::from(permission);

                        if !permission.contains(_permission_control::Permission::Any) {
                            let role = _error_stack::ResultExt::change_context(
                                _permission_control::sender_role(storage, sender),
                                _permission_control::Error::PermissionDenied {
                                    expected: permission.clone(),
                                    actual: _permission_control::Permission::NoPrivilege.into(),
                                },
                            )?;

                            if (*permission & *role).is_empty() {
                                return Err(_permission_control::Error::PermissionDenied {
                                    expected: permission,
                                    actual: role,
                                }
                                .into());
                            }
                        }
                        Ok(self)
                    }
                }
            })
        }
        _ => panic!("Only enums are supported"),
    }
}

fn find_permission(variant: &Variant) -> Option<syn::Expr> {
    variant
        .attrs
        .iter()
        .find(|attr| attr.path().is_ident("permission"))
        .and_then(|attr| attr.parse_args().ok())
}
