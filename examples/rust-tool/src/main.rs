use byte_smith::codec;

fn main() {
    let raw = std::fs::read("input.bin").unwrap_or_default();
    let msg = codec::decode(&raw);
    println!("{} bytes", msg.len());
}
