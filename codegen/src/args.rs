use include_crypt_crypto::key::EncryptionKey;
use proc_macro2::Span;
use std::convert::TryFrom;
use syn::parse::{Parse, ParseBuffer};

/// Arguments for symmetric encryption ciphers.
///
/// # Example
///
/// There's two ways this argument can be used.
/// 1. With a custom key:
/// ```text
/// "file.txt", 0xdeadbeef
/// ```
/// 2. With a random key
/// ```text
/// "file.txt"
/// ```
pub(crate) struct SymmetricArgs {
    /// The parsed file path.
    pub file_path: String,

    /// Flag whether the key was randomly generated.
    pub random_key: bool,

    /// The parsed encryption key.
    pub key: EncryptionKey,
}

impl Parse for SymmetricArgs {
    fn parse(input: &'_ ParseBuffer<'_>) -> syn::parse::Result<Self> {
        let file_path = input.parse::<syn::LitStr>()?;

        // If there's no key defined, generate one randomly.
        //
        let (random_key, key) = if input.parse::<syn::Token![,]>().is_err() {
            (true, EncryptionKey::default())
        } else {
            (
                false,
                EncryptionKey::try_from(&*input.parse::<syn::LitInt>()?.to_string())
                    .map_err(|e| syn::parse::Error::new(Span::call_site(), e))?,
            )
        };

        Ok(Self {
            file_path: file_path.value(),
            random_key,
            key,
        })
    }
}
