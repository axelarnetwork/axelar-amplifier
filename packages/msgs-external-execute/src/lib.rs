use itertools::Itertools;
use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{
    parse_macro_input, punctuated::Punctuated, Data, DataEnum, DeriveInput, Expr, Ident, ItemFn,
    Path, Signature, Stmt, Token,
};

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
    let route_function = build_route_implementation(data.clone());
    let execute_functions = build_execute_implementation(data);

    TokenStream::from(quote! {
        impl #enum_type {
            #route_function

            #(
                #execute_functions
            )*
        }
    })
}

fn build_route_implementation(data: DataEnum) -> proc_macro2::TokenStream {
    let (variant_args, unique_args) = variant_tokens_and_unique_args(data.clone());

    let rm = route_match(variant_args);

    let fs: Vec<_> = (0..unique_args.len())
        .map(|i| format_ident!("F{}", i))
        .collect();

    proc_macro2::TokenStream::from(quote! {
        pub fn route<T, #(#fs),*>(
            &self,
            deps: cosmwasm_std::DepsMut,
            env: cosmwasm_std::Env,
            info: cosmwasm_std::MessageInfo,
            original_sender: Addr,
            exec: T,
            #(#unique_args: #fs),*
        ) -> Result<cosmwasm_std::Response, axelar_wasm_std::permission_control::Error>
            where
            T: FnOnce(cosmwasm_std::DepsMut, cosmwasm_std::Env, cosmwasm_std::MessageInfo, Self) -> Result<cosmwasm_std::Response, axelar_wasm_std::error::ContractError>,
            #(#fs:FnOnce(cosmwasm_std::DepsMut, cosmwasm_std::Env, cosmwasm_std::MessageInfo, Self, T) -> Result<cosmwasm_std::Response, axelar_wasm_std::error::ContractError>),*
                {
            #rm
        }
    })
}

// Returns:
// - variant tokens: First tuple element is variant ident. Second is list of permitted contracts for that variant
// - unique arguments: List of permitted contracts (no duplicates)
fn variant_tokens_and_unique_args(data: DataEnum) -> (Vec<(Ident, Vec<Path>)>, Vec<Path>) {
    let mut variant_args: Vec<(Ident, Vec<Path>)> = vec![];
    let mut unique_args: Vec<Path> = vec![];

    for v in data.variants {
        let variant = v.ident.clone();
        for a in v.attrs.clone() {
            if let syn::Meta::List(l) = a.clone().meta {
                let attribute_name = l.path.segments.last().unwrap().ident.clone();
                if attribute_name.to_string() != "permit" {
                    continue;
                }

                let argument = a
                    .parse_args_with(Punctuated::<Expr, Token![,]>::parse_terminated)
                    .expect("cannot parse arguments");

                let permitted_contracts: Vec<Path> = argument
                    .into_iter()
                    .map(|arg| match arg {
                        Expr::Path(path) => path.path.clone(),
                        _ => panic!("expected a path"),
                    })
                    .collect();

                variant_args.push((variant.clone(), permitted_contracts.clone()));
                unique_args.append(&mut permitted_contracts.clone());
            }
        }
    }

    (variant_args, unique_args.into_iter().unique().collect())
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
        let mut info_new_sender = info.clone();
        info_new_sender.sender = original_sender.clone();
        #(
            let res = #routes(deps, env.clone(), info_new_sender.clone(), self.clone(), exec);
            if res.is_ok() {
                return Ok(res.unwrap());
            }
        )*

        Err(axelar_wasm_std::permission_control::Error::Unauthorized)
    })
}

fn build_execute_implementation(data: DataEnum) -> Vec<proc_macro2::TokenStream> {
    let (variant_args, unique_args) = variant_tokens_and_unique_args(data.clone());

    unique_args
        .into_iter()
        .map(|permitted_contract| {
            // execute functions ident
            let execute_fn_ident = format_ident!(
                "execute_from_{}",
                permitted_contract.get_ident().unwrap().to_string()
            );

            quote! {
                pub fn #execute_fn_ident <F0>(
                    deps: cosmwasm_std::DepsMut,
                    env: cosmwasm_std::Env,
                    info: cosmwasm_std::MessageInfo,
                    msg: ExecuteMsg,
                    exec: F0,
                ) -> Result<Response, axelar_wasm_std::error::ContractError>
                where
                    F0: FnOnce(
                        cosmwasm_std::DepsMut,
                        cosmwasm_std::Env,
                        cosmwasm_std::MessageInfo,
                        Self,
                    )
                        -> Result<cosmwasm_std::Response, axelar_wasm_std::error::ContractError>,
                {
                    match msg {
                        ExecuteMsg::RegisterChain { .. } => exec(deps, env, info, msg),
                        _ => Err(Error::InvalidExecuteMsg.into()),
                    }
                }
            }
        })
        .collect()
}

// Execute function attribute
#[proc_macro_attribute]
pub fn allow_external_execute(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);
    let block = &input.block;
    let sig = &input.sig;
    let vis = &input.vis;

    // Copied match
    let mut copy_block = block.clone();
    copy_block.stmts.clear();

    // Copied signature
    let mut copy_sig = Signature::from(sig.clone());
    copy_sig.ident = format_ident!("{}_copy", sig.ident);

    for st in block.stmts.clone() {
        match st.clone() {
            Stmt::Expr(expr, _) => match expr {
                Expr::Match(match_st) => {
                    copy_block.stmts.push(st);
                }
                _ => (),
            },
            _ => (),
        }
    }

    TokenStream::from(quote! {
        #vis #copy_sig {
            println!("This is a copy!");
            #copy_block
        }

        #vis #sig {
            #block
        }
    })
}
