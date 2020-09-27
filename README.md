![Rust](https://github.com/not-matthias/include_crypt/workflows/Rust/badge.svg)

# include_crypt
Safely embed files into your binary.

## Example

```rust
static FILE: EncryptedFile = include_crypt!(XOR, "../assets/file.txt");

fn main() {
    let decrypted = FILE.decrypt();
}
```

## How does it work? 

TODO

## Features

- `compression`: Compresses the file before encrypting it.
- `force-build`: Always runs the proc macro. 
