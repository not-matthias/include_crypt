use crate::{implementations::args::FileArgs, utils::read_file};
use include_crypt_crypto::xor::xor;
use proc_macro::TokenStream;

#[doc(hidden)]
pub(crate) fn impl_encrypt_xor(input: TokenStream) -> syn::Result<TokenStream> {
    let args: FileArgs = syn::parse(input)?;
    let mut file = read_file(&args.file_path)?;

    // Encrypt the file
    //
    xor(file.as_mut_slice(), &args.key);

    // Return the key and encrypted file
    //
    let bytes = syn::LitByteStr::new(&file, proc_macro2::Span::call_site());
    let key = args.key.as_str();

    Ok(quote::quote!((include_crypt::obfstr::obfconst!(#key), #bytes)).into())
}
