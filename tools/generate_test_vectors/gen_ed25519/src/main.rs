use ed25519_dalek::{PublicKey, SecretKey};
use rand_core::OsRng;

fn main() {
    println!("sk, pk");
    for _ in 0..=15 {
        let (sk, pk) = gen_key();
        println!(
            "make_tuple(from_hex(\"{}\"), from_hex(\"{}\")),",
            hex::encode(sk.to_bytes()),
            hex::encode(pk.as_bytes())
        );
    }
}

fn gen_key() -> (SecretKey, PublicKey) {
    let sk = SecretKey::generate(&mut OsRng);
    let pk = PublicKey::from(&sk);

    (sk, pk)
}
