use proc_macro::TokenStream;

mod aes;
mod args;
mod utils;
mod xor;

/// Encrypts a file with a random or custom key.
///
/// # Example
///
/// ## Custom key
///
/// ```
/// # use include_crypt_codegen::encrypt_xor;
/// let encrypted = encrypt_xor!("src/lib.rs", 0xdeadbeef);
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
/// let (nonce, encrypted) = encrypt_aes!("src/lib.rs", 0xdeadbeef);
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
