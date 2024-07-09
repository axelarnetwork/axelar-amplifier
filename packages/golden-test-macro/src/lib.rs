use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::Parse, parse::ParseStream, parse_macro_input, punctuated::Punctuated, Expr, ExprLit,
    ItemFn, Lit, Meta, Token,
};

struct MacroArgs {
    dir: Option<String>,
    path: Option<String>,
}

fn expr_to_string(expr: Expr) -> Option<String> {
    if let Expr::Lit(ExprLit {
        lit: Lit::Str(lit_str),
        ..
    }) = expr
    {
        Some(lit_str.value())
    } else {
        None
    }
}

impl Parse for MacroArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let parsed: Punctuated<Meta, Token![,]> =
            Punctuated::parse_terminated_with(input, Meta::parse)?;

        let mut dir = None;
        let mut path = None;

        for meta in parsed {
            if let Meta::NameValue(nv) = meta {
                if nv.path.is_ident("dir") {
                    dir = expr_to_string(nv.value);
                } else if nv.path.is_ident("path") {
                    path = expr_to_string(nv.value);
                }
            }
        }

        Ok(MacroArgs { dir, path })
    }
}

#[allow(clippy::test_attr_in_doctest)]
/// Allows a test to work with golden files. A `golden_file` variable will be defined that can be written to during the test.
/// This golden file will be checked or updated based on the test mode.
///
/// `cargo test` will check against the golden file.
/// `UPDATE_GOLDENFILES=1 cargo test` will update the golden file instead.
///
/// Optional arguments:
/// - `dir`: Override the golden files directory (default: "tests/goldenfiles")
/// - `path`: Override the golden file path for this test (default: derived from test name, e.g. module.func_name.txt)
///
/// # Examples
///
/// ```
/// use golden_test_macro::golden_test;
/// use std::io::Write;
///
/// #[golden_test(dir = "tests/files", path = "method.json")]
/// #[test]
/// fn test_method() {
///    writeln!(golden_file, "Hello, world!").unwrap();
/// }
/// ```
#[proc_macro_attribute]
pub fn golden_test(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as MacroArgs);
    let input = parse_macro_input!(item as ItemFn);
    let func_name = &input.sig.ident;
    let attrs = &input.attrs;
    let func_block = &input.block;

    let dir = match args.dir {
        Some(d) => quote! { #d },
        None => quote! { "tests/goldenfiles" },
    };

    let path = match args.path {
        Some(p) => quote! { #p },
        None => quote! { {
            let test_name = std::thread::current()
                .name()
                .unwrap()
                .to_string()
                .replace("::", ".");

            format!("{}.txt", test_name)
        } },
    };

    let expanded = quote! {
        #(#attrs)*
        fn #func_name() {
            use goldenfile::Mint;

            let mut mint = Mint::new(#dir);

            let golden_file_path = #path;

            let mut golden_file = mint.new_goldenfile(golden_file_path).unwrap();
            let _ = mint;
            let _ = golden_file_path;

            // Closure to capture golden_file
            (|| {
                #func_block
            })();

            // On drop, mint will check/update the golden file
        }
    };

    TokenStream::from(expanded)
}
