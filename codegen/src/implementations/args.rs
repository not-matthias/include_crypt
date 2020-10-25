use include_crypt_crypto::key::EncryptionKey;
use proc_macro2::Span;
use std::convert::TryFrom;
use syn::parse::{Parse, ParseBuffer};

/// Arguments for the file encryption implementations.
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
pub(crate) struct FileArgs {
    /// The parsed file path.
    pub file_path: String,

    /// The parsed encryption key.
    pub key: EncryptionKey,
}

impl Parse for FileArgs {
    fn parse(input: &'_ ParseBuffer<'_>) -> syn::parse::Result<Self> {
        let file_path = input.parse::<syn::LitStr>()?;

        // If there's no key defined, generate one randomly.
        //
        let key = if input.parse::<syn::Token![,]>().is_err() {
            EncryptionKey::default()
        } else {
            EncryptionKey::try_from(&*input.parse::<syn::LitInt>()?.to_string())
                .map_err(|e| syn::parse::Error::new(Span::call_site(), e))?
        };

        Ok(Self {
            file_path: file_path.value(),
            key,
        })
    }
}

pub(crate) enum EncryptionType {
    Xor,
    Aes,
}

impl TryFrom<String> for EncryptionType {
    type Error = ();

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "xor" => Ok(Self::Xor),
            "aes" => Ok(Self::Aes),
            _ => Err(()),
        }
    }
}

impl ToString for EncryptionType {
    fn to_string(&self) -> String {
        match self {
            EncryptionType::Xor => "Xor",
            EncryptionType::Aes => "Aes",
        }
        .to_string()
    }
}

pub(crate) struct FolderArgs {
    /// The encryption type which should be used to encrypt the files in the
    /// folder.
    pub encryption_type: EncryptionType,

    /// The parsed folder path.
    pub folder_path: String,
}

impl Parse for FolderArgs {
    fn parse(input: &'_ ParseBuffer<'_>) -> syn::parse::Result<Self> {
        let encryption_type = input.parse::<syn::LitStr>()?;
        let _ = input.parse::<syn::Token![,]>()?;
        let folder_path = input.parse::<syn::LitStr>()?;

        let encryption_type = EncryptionType::try_from(encryption_type.value())
            .map_err(|_| syn::Error::new(Span::mixed_site(), "Invalid encryption type"))?;

        Ok(Self {
            encryption_type,
            folder_path: folder_path.value(),
        })
    }
}
