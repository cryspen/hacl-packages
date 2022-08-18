use rand::rngs::OsRng;
use x25519_dalek_ng::{PublicKey, StaticSecret};

fn main() {
    println!("sk, pk");
    for _ in 0..=15 {
        let (sk, pk) = gen_key();
        println!(
            "{}, {}",
            hex::encode(sk.to_bytes()),
            hex::encode(pk.as_bytes())
        );
    }
}

fn gen_key() -> (StaticSecret, PublicKey) {
    let mut rng = OsRng::default();

    let sk = StaticSecret::new(&mut rng);
    let pk = PublicKey::from(&sk);

    (sk, pk)
}
