use crate::{key::EncryptionKey, utils::read_file};
use syn::{
    export::TokenStream,
    parse::{Parse, ParseBuffer},
};

struct XorArgs {
    /// The parsed file path.
    file_path: String,

    /// Flag whether the key was randomly generated.
    random_key: bool,

    /// The parsed encryption key.
    key: EncryptionKey,
}

impl Parse for XorArgs {
    fn parse(input: &'_ ParseBuffer<'_>) -> syn::parse::Result<Self> {
        let file_path = input.parse::<syn::LitStr>()?;

        // If there's no key defined, generate one randomly.
        //
        let (random_key, key) = if input.parse::<syn::Token![,]>().is_err() {
            (true, rand::random::<u64>())
        } else {
            (false, input.parse::<syn::LitInt>()?.base10_parse::<u64>().unwrap())
        };

        Ok(Self {
            file_path: file_path.value(),
            random_key,
            key: EncryptionKey::new(key),
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
        .map(|d| d.into_iter().zip(&*args.key).map(|(d, k)| *d ^ *k).collect::<Vec<_>>())
        .flatten()
        .collect::<Vec<_>>();

    // If we generated a random key, we have to return it too.
    //
    let bytes = syn::LitByteStr::new(&file, proc_macro2::Span::call_site());
    if args.random_key {
        let key = args.key.as_u64();
        Ok(quote::quote!((#key, #bytes)).into())
    } else {
        Ok(quote::quote!(#bytes).into())
    }
}
