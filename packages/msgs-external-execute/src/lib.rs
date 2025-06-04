use cosmwasm_std::Response;
use itertools::Itertools;
use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{format_ident, quote};
use syn::{punctuated::Punctuated, Data, DataEnum, DeriveInput, Expr, Ident, Path, Token};

#[proc_macro_derive(ExternalExecute, attributes(permit))]
pub fn hello_macro_derive(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let ident = input.ident.clone();

    match input.data.clone() {
        Data::Enum(data) => build_implementation(ident, data),
        _ => panic!("Only enums are supported"),
    }
}

fn build_implementation(enum_type: Ident, data: DataEnum) -> TokenStream {
    let route_function = build_route_implementation(data);

    TokenStream::from(quote! {
        impl #enum_type {
            #route_function
        }
    })
}

fn build_route_implementation(data: DataEnum) -> proc_macro2::TokenStream {
    let mut route_fn_tokens: Vec<(Ident, Vec<Path>)> = vec![];
    let mut unique_args: Vec<Path> = vec![];

    for v in data.variants {
        println!("Variant: {:?}", v.ident.clone());
        let variant = v.ident.clone();
        for a in v.attrs.clone() {
            if let syn::Meta::List(l) = a.clone().meta {
                let attribute_name = l.path.segments.last().unwrap().ident.clone();
                if attribute_name.to_string() != "permit" {
                    continue;
                }

                println!("Last {:?}", l.path.segments.last().clone()); // permit

                let argument = a
                    .parse_args_with(Punctuated::<Expr, Token![,]>::parse_terminated)
                    .expect("cannot parse arguments");

                let mut permitted_contracts: Vec<Path> = argument
                    .into_iter()
                    .map(|arg| match arg {
                        Expr::Path(path) => path.path.clone(),
                        _ => panic!("expected a path"),
                    })
                    .collect();

                route_fn_tokens.push((variant.clone(), permitted_contracts.clone()));
                unique_args.append(&mut permitted_contracts.clone());
            }
        }
    }

    let unique_args: Vec<Path> = unique_args
    .into_iter()
    .unique()
    .collect();

    println!("Tokens: {:?}", route_fn_tokens.clone());
    println!("Arguments: {:?}", unique_args);

    let rm = route_match(route_fn_tokens);
    let fs: Vec<_> = (0..unique_args.len()).map(|i| format_ident!("F{}", i)).collect();
    let cs: Vec<_> = (0..unique_args.len()).map(|i| format_ident!("C{}", i)).collect();

    proc_macro2::TokenStream::from(quote! {
        pub fn route<#(#fs),*,#(#cs),*>(
            &self,
            deps: cosmwasm_std::DepsMut,
            original_sender: Addr,
            #(#unique_args: #fs),*
        ) -> Result<cosmwasm_std::Response, axelar_wasm_std::permission_control::Error>
            where #(#fs:FnOnce(cosmwasm_std::DepsMut, Addr, Self) -> error_stack::Result<cosmwasm_std::Response, #cs>),*,
            #(#cs: error_stack::Context),*
                {
            #rm
        }
    })
}

fn route_match(routing_fns: Vec<(Ident, Vec<Path>)>) -> proc_macro2::TokenStream {
    let (variants, routes): (Vec<_>, Vec<_>) = routing_fns.into_iter().unzip();
    let sends = sends(routes.into_iter().flatten().collect());

    proc_macro2::TokenStream::from(quote! {
        match self {
            #(#variants => {#sends}),*
        }
    })
}

fn sends(routes: Vec<Path>) -> proc_macro2::TokenStream {
    proc_macro2::TokenStream::from(quote! {
        #(
            let res = #routes(deps, original_sender.clone(), self.clone());
            if res.is_ok() {
                return Ok(res.unwrap());
            }
        )*

        Err(axelar_wasm_std::permission_control::Error::Unauthorized)
    })
}
