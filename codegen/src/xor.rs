use crate::utils::read_file;
use syn::{
    export::TokenStream,
    parse::{Parse, ParseBuffer},
};

#[derive(Debug, Default)]
struct XorArgs {
    file_path: String,
    key: Vec<u8>,
}

impl Parse for XorArgs {
    fn parse(input: &'_ ParseBuffer<'_>) -> syn::parse::Result<Self> {
        // Parse `"file.txt", 0xDEADBABE`
        //
        let file_path = input.parse::<syn::LitStr>()?;
        input.parse::<syn::Token![,]>()?;
        let key = input.parse::<syn::LitInt>()?;

        // Create a vector from the key:
        // 1. Convert to hex
        // 2. Get two characters
        // 3. Convert those to an u8
        //
        let hex_key = format!("{:x?}", key.base10_parse::<u64>().unwrap());
        let key = hex_key
            .chars()
            .collect::<Vec<_>>()
            .chunks(2)
            .map(|c| c.iter().collect::<String>())
            .map(|s| u8::from_str_radix(&s, 16).unwrap_or_default())
            .collect::<Vec<_>>();

        Ok(Self {
            file_path: file_path.value(),
            key,
        })
    }
}

#[doc(hidden)]
pub(crate) fn impl_encrypt_xor(input: TokenStream) -> syn::Result<TokenStream> {
    let args: XorArgs = syn::parse(input)?;

    // Read the file and encrypt it
    //
    let mut file = read_file(&args.file_path)?;
    let file = file
        .as_mut_slice()
        .chunks_mut(args.key.len())
        .map(|d| d.into_iter().zip(&args.key).map(|(d, k)| *d ^ *k).collect::<Vec<_>>())
        .flatten()
        .collect::<Vec<_>>();

    let bytes = syn::LitByteStr::new(&file, proc_macro2::Span::call_site());
    Ok(quote::quote!(#bytes).into())
}
