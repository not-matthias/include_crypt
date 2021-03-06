use include_crypt::{include_crypt, EncryptedFile};

static NO_KEY: EncryptedFile = include_crypt!(AES, "examples/example.data");
static CUSTOM_KEY: EncryptedFile = include_crypt!(AES, "examples/example.data", 0xdeadbeef);

fn main() {
    println!("{:?}", NO_KEY.decrypt());
    println!("{:?}", NO_KEY.decrypt_str());

    println!("{:?}", CUSTOM_KEY.decrypt());
    println!("{:?}", CUSTOM_KEY.decrypt_str());
}
