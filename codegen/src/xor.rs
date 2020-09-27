use crate::{args::SymmetricArgs, utils::read_file};
use include_crypt_crypto::xor::xor;
use syn::export::TokenStream;

#[doc(hidden)]
pub(crate) fn impl_encrypt_xor(input: TokenStream) -> syn::Result<TokenStream> {
    let args: SymmetricArgs = syn::parse(input)?;
    let mut file = read_file(&args.file_path)?;

    // Encrypt the file
    //
    xor(file.as_mut_slice(), &args.key);

    // If we generated a random key, we have to return it too.
    //
    let bytes = syn::LitByteStr::new(&file, proc_macro2::Span::call_site());
    if args.random_key {
        let key = args.key.as_str();
        Ok(quote::quote!((#key, #bytes)).into())
    } else {
        Ok(quote::quote!(#bytes).into())
    }
}
