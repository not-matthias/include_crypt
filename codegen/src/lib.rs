use proc_macro::TokenStream;

mod utils;
mod xor;

/// Encrypts a file with a random or custom xor key.
///
/// # Example
///
/// There's two ways to call this function.
///
/// ## Custom key
///
/// ```
/// # use include_crypt_codegen::encrypt_xor;
/// let encrypted = encrypt_xor!("src/lib.rs", 0xDEADBABE);
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
