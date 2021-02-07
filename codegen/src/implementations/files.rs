use crate::{
    implementations::{
        aes,
        args::{EncryptionType, FolderArgs},
        xor,
    },
    utils,
};
use proc_macro::TokenStream;
use quote::quote;
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    path::PathBuf,
};

pub(crate) fn impl_include_files(input: TokenStream) -> syn::Result<TokenStream> {
    let args: FolderArgs = syn::parse(input)?;

    // Create the correct path to the file
    //
    let folder_path = PathBuf::from(args.folder_path);
    let folder_path = if folder_path.is_relative() {
        PathBuf::from(
            std::env::var("CARGO_MANIFEST_DIR").expect("Failed to fine 'CARGO_MANIFEST_DIR' environment variable"),
        )
        .join(folder_path)
    } else {
        folder_path
    };

    // Check if the folder exists
    //
    if !folder_path.exists() {
        return Err(utils::error_mapping(format!(
            "Folder {:?} could not be found.",
            folder_path
        )));
    };

    // Find the paths of all the files in the folder
    //
    let file_paths = glob::glob(format!("{}/**/*", folder_path.display()).as_str())
        .map_err(utils::error_mapping)?
        .filter_map(Result::ok)
        .filter(|path| {
            std::fs::metadata(path)
                .map(|metadata| metadata.is_file())
                .unwrap_or_default()
        })
        .collect::<Vec<_>>();

    // Encrypt all the files
    //
    let encryption_type = args.encryption_type;
    let files = file_paths
        .clone()
        .into_iter()
        .map(|file| file.display().to_string())
        .map(|file| {
            match &encryption_type {
                EncryptionType::Xor => xor::impl_encrypt_xor(TokenStream::from(quote!(#file))),
                EncryptionType::Aes => aes::impl_encrypt_aes(TokenStream::from(quote!(#file))),
            }
            .expect("Failed to encrypt file")
        })
        .map(proc_macro2::TokenStream::from)
        .collect::<Vec<_>>();

    // Convert the absolute paths into relative paths
    //
    let paths: Vec<String> = file_paths
        .into_iter()
        .map(|path| {
            path.strip_prefix(&folder_path)
                .map(|path| path.display().to_string())
                .unwrap_or_default()
        })
        .map(|path| {
            let path = path.replace("\\", "/");

            let mut hasher = DefaultHasher::new();
            path.hash(&mut hasher);
            hasher.finish().to_string()
        })
        .collect::<Vec<_>>();

    // Create an array of encrypted files with their name:
    // [ (name, file), (name, file) ]
    //
    let expanded = match encryption_type {
        EncryptionType::Xor => quote!(
            [
                #((
                    #paths,
                    {
                        let (key, data) = #files;
                        include_crypt::EncryptedFile::new(data, include_crypt::EncryptionType::Xor(key))
                    }
                ),)*
            ]
        ),
        EncryptionType::Aes => quote!(
            [
                #((
                    #paths,
                    {
                        let (key, nonce, data) = #files;
                        include_crypt::EncryptedFile::new(data, include_crypt::EncryptionType::Aes(key, nonce))
                    }
                ),)*
            ]
        ),
    };

    Ok(expanded.into())
}
