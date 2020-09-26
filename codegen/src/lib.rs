use proc_macro::TokenStream;

mod utils;
mod xor;

/// Encrypts a file with a random xor key.
///
/// # Example
///
/// There's two ways to call this function.
///
/// ## Custom key
///
/// ```
/// let encrypted = encrypt_xor!("file.txt", 0xDEADBABE); 
/// ```
///
/// ## Random key
///
/// ```
/// let (key, encrypted) = encrypt_xor!("file.txt"); 
/// ```
#[proc_macro]
pub fn encrypt_xor(input: TokenStream) -> TokenStream {
    match xor::impl_encrypt_xor(input) {
        Ok(ts) => ts.into(),
        Err(err) => err.to_compile_error().into(),
    }
}
