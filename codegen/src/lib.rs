use proc_macro::TokenStream;

mod utils;
mod xor;

/// Encrypts a file with a random xor key.
///
/// # Example
///
/// ```
/// let encrypted = encrypt_xor!("file.txt", 0xDEADBABE); 
/// ```
#[proc_macro]
pub fn encrypt_xor(input: TokenStream) -> TokenStream {
    println!("{}", &input);

    match xor::impl_encrypt_xor(input) {
        Ok(ts) => ts.into(),
        Err(err) => err.to_compile_error().into(),
    }
}
