use implementations::{aes, files, xor};
use proc_macro::TokenStream;

mod implementations;
mod utils;

/// Encrypts a file with a random or custom key.
///
/// # Example
///
/// ## Custom key
///
/// ```
/// # use include_crypt_codegen::encrypt_xor;
/// let (key, encrypted) = encrypt_xor!("src/lib.rs", 0xdeadbeef);
/// ```
///
/// ## Random key
///
/// ```
/// # use include_crypt_codegen::encrypt_xor;
/// let (key, encrypted) = encrypt_xor!("src/lib.rs");
/// ```
#[proc_macro]
pub fn encrypt_xor(input: TokenStream) -> TokenStream {
    match xor::impl_encrypt_xor(input) {
        Ok(ts) => ts,
        Err(err) => err.to_compile_error().into(),
    }
}

/// Encrypts a file with a random or custom key.
///
/// # Example
///
/// ## Custom key
///
/// ```
/// # use include_crypt_codegen::encrypt_aes;
/// let (key, nonce, encrypted) = encrypt_aes!("src/lib.rs", 0xdeadbeef);
/// ```
///
/// ## Random key
///
/// ```
/// # use include_crypt_codegen::encrypt_aes;
/// let (key, nonce, encrypted) = encrypt_aes!("src/lib.rs");
/// ```
#[proc_macro]
pub fn encrypt_aes(input: TokenStream) -> TokenStream {
    match aes::impl_encrypt_aes(input) {
        Ok(ts) => ts,
        Err(err) => err.to_compile_error().into(),
    }
}

/// Encrypts all the files in the specified folder.
///
/// # Example
///
/// ```
/// # use include_crypt_codegen::include_files;
/// let files = include_files!("XOR", "src");
/// ```
#[proc_macro]
pub fn include_files(input: TokenStream) -> TokenStream {
    match files::impl_include_files(input) {
        Ok(ts) => ts,
        Err(err) => err.to_compile_error().into(),
    }
}
