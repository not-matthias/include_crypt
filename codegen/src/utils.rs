use std::{fs::File, io::Read, path::PathBuf};

pub(crate) fn error_mapping<E: std::fmt::Display>(error: E) -> syn::Error {
    syn::Error::new(proc_macro2::Span::call_site(), error)
}

/// Opens the specified file and returns the content.
pub(crate) fn read_file<P: Into<PathBuf>>(file_path: P) -> syn::Result<Vec<u8>> {
    let file_path = file_path.into();

    // Create the correct path to the file
    //
    let file_path = if file_path.is_relative() {
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join(file_path)
    } else {
        file_path
    };

    // Check if the file exists
    //
    if !file_path.exists() {
        return Err(error_mapping(format!("File {:?} could not be found.", file_path)));
    };

    // Open and read file.
    //
    let mut file = File::open(&file_path).map_err(error_mapping)?;
    let file_size = file.metadata().map_err(error_mapping)?.len();

    let mut file_bytes = Vec::with_capacity(file_size as usize);
    file.read_to_end(&mut file_bytes).map_err(error_mapping)?;

    // Compress the file if the feature is set
    //
    #[cfg(feature = "compression")]
    {
        use std::io::Write;

        let mut encoder = libflate::deflate::Encoder::new(Vec::with_capacity(file_bytes.len()));
        encoder.write_all(&file_bytes).map_err(error_mapping)?;
        encoder.finish().into_result().map_err(error_mapping)
    }

    #[cfg(not(feature = "compression"))]
    Ok(file_bytes)
}
