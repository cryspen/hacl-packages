use serde::{Deserialize, Serialize};
use sha2::{digest::DynDigest, Digest, Sha224, Sha256, Sha384, Sha512};

#[derive(Debug, Serialize, Deserialize)]
struct Test {
    msg: String,
    md: String,
}

fn main() {
    let hash = std::env::args().nth(1).unwrap();

    let mut tests = Vec::new();

    for i in 0..=1024 {
        let msg = "A".repeat(i);

        let mut hasher: Box<dyn DynDigest> = match hash.as_ref() {
            "sha2-224" => Box::new(Sha224::new()),
            "sha2-256" => Box::new(Sha256::new()),
            "sha2-384" => Box::new(Sha384::new()),
            "sha2-512" => Box::new(Sha512::new()),
            _ => {
                eprintln!("Invalid argument! Exiting.");
                std::process::exit(1);
            }
        };

        hasher.update(msg.as_bytes());

        let md = hasher.finalize();

        tests.push(Test {
            msg: hex::encode(msg.as_bytes()),
            md: hex::encode(md.as_ref()),
        });
    }

    let out = serde_json::to_string_pretty(&tests).unwrap();

    println!("{}", out);
}
