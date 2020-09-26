use include_crypt::include_crypt;

fn main() {
    let test = include_crypt!(XOR, "codegen/examples/test.data");
    // println!("{:x?}", FILE);
}
