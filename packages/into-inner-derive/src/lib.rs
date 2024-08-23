use proc_macro::TokenStream;
use quote::quote;
use syn::{DeriveInput, Fields};

#[proc_macro_derive(IntoInner)]
pub fn into_inner_derive(input: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(input).unwrap();

    let name = &ast.ident;
    let ty = match ast.data {
        syn::Data::Struct(val) => match val.fields {
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                fields.unnamed.first().map(|field| field.ty.to_owned())
            }
            _ => None,
        },
        _ => None,
    };

    match ty {
        Some(ty) => quote! {
            impl #name {
                pub fn into_inner(self) -> #ty {
                    self.0
                }
            }
        }
        .into(),
        None => panic!("only newtype structs are supported"),
    }
}
