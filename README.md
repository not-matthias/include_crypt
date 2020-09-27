![Rust](https://github.com/not-matthias/include_crypt/workflows/Rust/badge.svg)

# include_crypt
Safely embed files into your binary.

## Example

```
static file: EncryptedFile = include_crypt!("../assets/file.txt");

fn main() {
    let decrypted = file.decrypted();
}
```

## How does it work? 

TODO

## Features

- `aes`
- `rsa`
- `xor`
- `checksum`
