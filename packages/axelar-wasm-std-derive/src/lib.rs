use proc_macro::TokenStream;
use quote::quote;
use syn::DeriveInput;

#[proc_macro_derive(IntoContractError)]
pub fn into_contract_error_derive(input: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(input).unwrap();

    let name = &ast.ident;

    let gen = quote! {
        use axelar_wasm_std::ContractError as _ContractError;

        impl From<#name> for _ContractError {
            fn from(error: #name) -> Self {
                use report::LoggableError;
                use error_stack::report;

                LoggableError::from(&report!(error)).into()
            }
        }
    };

    gen.into()
}
