use itertools::Itertools;
use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::punctuated::Punctuated;
use syn::{Data, DataEnum, DeriveInput, Expr, Ident, Path, Token};

const ATTRIBUTE_NAME: &str = "permit";

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
    let execute_functions = build_execute_implementation(data.clone());

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
    let (variant_args, unique_args) = variant_tokens_and_unique_args(data);

    let rm = route_match(variant_args);

    let fs: Vec<_> = (0..unique_args.len())
        .map(|i| format_ident!("F{}", i))
        .collect();

    quote! {
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
    }
}

fn route_match(routing_fns: Vec<(Ident, Vec<Path>)>) -> proc_macro2::TokenStream {
    let (variants, routes): (Vec<_>, Vec<_>) = routing_fns.into_iter().unzip();
    let sends = sends(routes.clone());

    quote! {
        let mut info_new_sender = info.clone();
        info_new_sender.sender = original_sender.clone();

        match self {
            #(ExecuteMsg::#variants {..} => {#sends}),*
            _ => Err(axelar_wasm_std::permission_control::Error::WrongVariant),
        }
    }
}

fn sends(routes: Vec<Vec<Path>>) -> Vec<proc_macro2::TokenStream> {
    routes
    .into_iter()
    .map(|paths| {
        quote! {
            #(
                let res = #paths(deps, env.clone(), info_new_sender.clone(), self.clone(), exec);
                if res.is_ok() {
                    return Ok(res.unwrap());
                }
            )*

            Err(axelar_wasm_std::permission_control::Error::Unauthorized)
        }
    })
    .collect()
}

// Returns
// - variant tokens: First tuple element is variant identifier. Second is list of permitted contracts for that variant
// - unique arguments: List of permitted contracts (no duplicates)
fn variant_tokens_and_unique_args(data: DataEnum) -> (Vec<(Ident, Vec<Path>)>, Vec<Path>) {
    let mut variant_args: Vec<(Ident, Vec<Path>)> = vec![];
    let mut unique_args: Vec<Path> = vec![];

    for v in data.variants {
        let variant = v.ident.clone();
        for a in v.attrs.clone() {
            if let syn::Meta::List(l) = a.clone().meta {
                let attribute_name = l.path.segments.last().unwrap().ident.clone();
                if attribute_name != ATTRIBUTE_NAME {
                    continue;
                }

                let argument = a
                    .parse_args_with(Punctuated::<Expr, Token![,]>::parse_terminated)
                    .expect("cannot parse arguments");

                let permitted_contracts: Vec<Path> = argument
                    .iter()
                    .map(|arg| match arg {
                        Expr::Path(path) => path.path.clone(),
                        _ => panic!("could not parse permitted contract"),
                    })
                    .collect();

                variant_args.push((variant.clone(), permitted_contracts.clone()));
                unique_args.append(&mut permitted_contracts.clone());
            }
        }
    }

    (variant_args, unique_args.into_iter().unique().collect())
}

// This computes the inverse of variant_tokens_and_unique_args's variant args.
// Returns: Vector of tuples where the first element is a permitted contract, and the second
// is a vector of all variants that contract is permitted for.
fn variants_for_contract(
    variant_args: Vec<(Ident, Vec<Path>)>,
    unique_args: Vec<Path>,
) -> Vec<(Path, Vec<Ident>)> {
    // TODO: We can optimize further by sorting. Although, since this executes at compile time, this simpler
    // implementation may be sufficient.
    unique_args
        .into_iter()
        .map(|permitted_contract| {
            let mut variants: Vec<Ident> = vec![];
            for (v, paths) in variant_args.clone() {
                for p in paths {
                    if p.get_ident()
                        .unwrap()
                        .eq(permitted_contract.get_ident().unwrap())
                    {
                        variants.push(v.clone());
                        break;
                    }
                }
            }

            (permitted_contract, variants)
        })
        .collect()
}

fn build_execute_implementation(data: DataEnum) -> Vec<proc_macro2::TokenStream> {
    let (variant_args, unique_args) = variant_tokens_and_unique_args(data.clone());
    let match_cases = variants_for_contract(variant_args, unique_args.clone());

    match_cases
        .into_iter()
        .map(|(contract, variants)| {
            // execute functions ident
            let execute_fn_ident =
                format_ident!("execute_from_{}", contract.get_ident().unwrap().to_string());

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
                        #(ExecuteMsg::#variants { .. } => {exec(deps, env, info, msg)}),*
                        _ => Err(Error::InvalidExecuteMsg.into()),
                    }
                }
            }
        })
        .collect()
}
