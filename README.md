![Rust](https://github.com/not-matthias/include_crypt/workflows/Rust/badge.svg)

# include_crypt
Safely embed files into your binary.

## Example

```rust
use include_crypt::{include_crypt, EncryptedFile};

static FILE: EncryptedFile = include_crypt!("assets/file.txt");

fn main() {
    let decrypted = FILE.decrypt();
    let decrypted_str = FILE.decrypt_str();
}

```

You can also select a encryption algorithm and specify your custom key. In this example, the key will be randomly generated.

## How does it work? 

TODO

## Features

- `compression`: Compresses the file before encrypting it.
- `force-build`: Always runs the proc macro. This should be used for testing, because the procedural macro doesn't detect file changes.
