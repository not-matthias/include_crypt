use include_crypt::{include_crypt, EncryptedFile};

static NO_KEY: EncryptedFile = include_crypt!(XOR, "examples/example.data");
static CUSTOM_KEY: EncryptedFile = include_crypt!(XOR, "examples/example.data", 0xdeadbeef);

fn main() {
    println!("{:?}", NO_KEY);
    println!("{:?}", NO_KEY.decrypt());
    println!("{:?}", NO_KEY.decrypt_str());

    println!("{:?}", CUSTOM_KEY);
    println!("{:?}", CUSTOM_KEY.decrypt());
    println!("{:?}", CUSTOM_KEY.decrypt_str());
}
