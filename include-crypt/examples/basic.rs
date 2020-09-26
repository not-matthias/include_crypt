use include_crypt::include_crypt;

fn main() {
    let test = include_crypt!(XOR, "include-crypt/examples/test.data");
    println!("{:x?}", test);
}
