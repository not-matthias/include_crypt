use crate::{args::SymmetricArgs, utils::read_file};
use include_crypt_crypto::{
    aes::{aes_encrypt, AES_NONCE_LEN},
    key::EncryptionKey,
};
use syn::export::TokenStream;

#[doc(hidden)]
pub(crate) fn impl_encrypt_aes(input: TokenStream) -> syn::Result<TokenStream> {
    let args: SymmetricArgs = syn::parse(input)?;
    let mut file = read_file(&args.file_path)?;

    // Encrypt the file
    //
    let nonce = EncryptionKey::random(AES_NONCE_LEN);
    aes_encrypt(file.as_mut_slice(), &args.key, &nonce);

    // Return the bytes, nonce and random generated key.
    //
    let nonce = nonce.as_str();
    let bytes = syn::LitByteStr::new(&file, proc_macro2::Span::call_site());

    if args.random_key {
        let key = args.key.as_str();
        Ok(quote::quote!((#key, #nonce, #bytes)).into())
    } else {
        Ok(quote::quote!((#nonce, #bytes)).into())
    }
}
