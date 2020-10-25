use crate::{
    implementations::args::FileArgs,
    utils::{error_mapping, read_file},
};
use include_crypt_crypto::{
    aes::{aes_encrypt, AES_NONCE_LEN},
    key::EncryptionKey,
};
use syn::export::TokenStream;

#[doc(hidden)]
pub(crate) fn impl_encrypt_aes(input: TokenStream) -> syn::Result<TokenStream> {
    let args: FileArgs = syn::parse(input)?;
    let mut file = read_file(&args.file_path)?;

    // Encrypt the file
    //
    let nonce = EncryptionKey::random(AES_NONCE_LEN);
    aes_encrypt(file.as_mut_slice(), &args.key, &nonce).map_err(|e| error_mapping(e.to_string()))?;

    // Return the key, nonce and encrypted file
    //
    let nonce = nonce.as_str();
    let bytes = syn::LitByteStr::new(&file, proc_macro2::Span::call_site());
    let key = args.key.as_str();

    Ok(quote::quote!((obfstr::obfconst!(#key), obfstr::obfconst!(#nonce), #bytes)).into())
}
