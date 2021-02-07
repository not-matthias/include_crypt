![Rust](https://github.com/not-matthias/include_crypt/workflows/Rust/badge.svg)
[![crates.io](https://img.shields.io/crates/v/include-crypt.svg)](https://crates.io/crates/include-crypt)
[![docs.rs](https://docs.rs/include-crypt/badge.svg)](https://docs.rs/include-crypt)

# include_crypt
Safely* embed files into your binary.

## Example

```rust
use include_crypt::{include_crypt, EncryptedFile};

static FILE: EncryptedFile = include_crypt!("assets/file.txt");

fn main() {
    let decrypted = FILE.decrypt();
    let decrypted_str = FILE.decrypt_str();
}
```

You can also select an encryption algorithm and specify your custom key. In this example, the key will be randomly generated. For more information see the [`include-crypt/examples/`](./include-crypt/examples) folder.

## Why?

When you use `include_str` or `include_bytes` the file content will be placed in the `.data` section of the binary. You can then use tools like `binwalk` to automatically extract these files. If you included a text file, you could also use `strings` to find the contents.

By encrypting the file, you can essentially hide all the signatures and magic numbers that are used to identify files in the binary. Of course the bytes  are still in the `.data` section, but now they are encrypted. If another person wanted to extract the file, they would need to manually find the code which decrypts the bytes.

Extracting the file without the tool is certainly doable for a somewhat experienced reverse engineer, but you can only do it by hand. It's essentially just security through obscurity. If you are interested, you can check out [this article on how to reverse-engineer (proprietary) file formats](https://en.wikibooks.org/wiki/Reverse_Engineering/File_Formats) or the Wikipedia page with a decent [List of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures). 

## Features

- `compression`: Compresses the file before encrypting it.
- `force-build`: Always runs the proc macro. This should be used for testing, because the procedural macro doesn't detect file changes.
