mod test_util;
use test_util::*;

use hacl_star::aead::{hacl_aes_available, Aead, Algorithm, Error};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(non_snake_case)]
struct AeadTestVector {
    algorithm: String,
    generatorVersion: String,
    numberOfTests: usize,
    notes: Option<Value>, // text notes (might not be present), keys correspond to flags
    header: Vec<Value>,   // not used
    testGroups: Vec<TestGroup>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(non_snake_case)]
struct TestGroup {
    ivSize: usize,
    keySize: usize,
    tagSize: usize,
    r#type: String,
    tests: Vec<Test>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(non_snake_case)]
struct Test {
    tcId: usize,
    comment: String,
    key: String,
    iv: String,
    aad: String,
    msg: String,
    ct: String,
    tag: String,
    result: String,
    flags: Vec<String>,
}

impl ReadFromFile for AeadTestVector {}

#[allow(non_snake_case)]
#[test]
fn test_wycheproof() {
    let aes_gcm_tests: AeadTestVector =
        AeadTestVector::from_file("tests/wycheproof/aes_gcm_test.json");
    let chacha_poly_tests: AeadTestVector =
        AeadTestVector::from_file("tests/wycheproof/chacha20_poly1305_test.json");

    let num_tests = aes_gcm_tests.numberOfTests + chacha_poly_tests.numberOfTests;
    let mut skipped_tests = 0;
    let mut tests_run = 0;
    assert_eq!(aes_gcm_tests.algorithm, "AES-GCM");
    assert_eq!(chacha_poly_tests.algorithm, "CHACHA20-POLY1305");

    test_group(aes_gcm_tests, &mut skipped_tests, &mut tests_run);
    test_group(chacha_poly_tests, &mut skipped_tests, &mut tests_run);

    fn test_group(test_vec: AeadTestVector, skipped_tests: &mut usize, tests_run: &mut usize) {
        for testGroup in test_vec.testGroups.iter() {
            assert_eq!(testGroup.r#type, "AeadTest");
            let algorithm = match test_vec.algorithm.as_str() {
                "AES-GCM" => match testGroup.keySize {
                    128 => Algorithm::Aes128Gcm,
                    256 => Algorithm::Aes256Gcm,
                    _ => {
                        // not implemented
                        println!("Only AES 128 and 256 are implemented.");
                        *skipped_tests += testGroup.tests.len();
                        continue;
                    }
                },
                "CHACHA20-POLY1305" => {
                    assert_eq!(testGroup.keySize, 256);
                    Algorithm::Chacha20Poly1305
                }
                _ => panic!("Unknown algorithm {:?}", test_vec.algorithm),
            };
            if !unsafe { hacl_aes_available() }
                && (algorithm == Algorithm::Aes128Gcm || algorithm == Algorithm::Aes256Gcm)
            {
                println!("⚠️  AES NOT AVAILABLE ON THIS PLATFORM!");
                *skipped_tests += testGroup.tests.len();
                continue;
            }
            let invalid_iv = if testGroup.ivSize != 96 { true } else { false };

            for test in testGroup.tests.iter() {
                let valid = test.result.eq("valid");
                if invalid_iv {
                    // AEAD requires input of a 12-byte nonce.
                    let nonce = hex_str_to_bytes(&test.iv);
                    assert!(nonce.len() != 12);
                    *skipped_tests += 1;
                    continue;
                }
                let invalid_iv = if test.comment == "invalid nonce size" || invalid_iv {
                    true
                } else {
                    false
                };
                println!("Test {:?}: {:?}", test.tcId, test.comment);
                let nonce = hex_str_to_bytes(&test.iv);
                let msg = hex_str_to_bytes(&test.msg);
                let aad = hex_str_to_bytes(&test.aad);
                let exp_cipher = hex_str_to_bytes(&test.ct);
                let exp_tag = hex_str_to_bytes(&test.tag);
                let key = hex_str_to_bytes(&test.key);

                let cipher = match Aead::new(algorithm, &key) {
                    Ok(c) => c,
                    Err(_) => {
                        println!("⚠️  Skipping {:?} because it's not available.", algorithm);
                        *skipped_tests += 1;
                        continue;
                    }
                };
                let (ctxt, tag) = match cipher.encrypt(&msg, &nonce, &aad) {
                    Ok(v) => v,
                    Err(e) => {
                        if invalid_iv {
                            assert_eq!(e, Error::InvalidNonce);
                        } else {
                            println!("Encrypt failed unexpectedly {:?}", e);
                            assert!(false);
                        }
                        *tests_run += 1;
                        continue;
                    }
                };
                if valid {
                    assert_eq!(tag, exp_tag);
                } else {
                    assert_ne!(tag, exp_tag);
                }
                assert_eq!(ctxt, exp_cipher);
                let ctxt_comb = cipher.encrypt_combined(&msg, &nonce, &aad).unwrap();
                assert_eq!(
                    ctxt_comb.split_at(ctxt_comb.len() - cipher.tag_size()),
                    (&ctxt[..], &tag[..])
                );
                let mut in_place_payload = msg.clone();
                let tag_in_place = cipher
                    .encrypt_in_place(&mut in_place_payload, &nonce, &aad)
                    .unwrap();
                assert_eq!(
                    (&in_place_payload[..], &tag_in_place[..]),
                    (&ctxt[..], &tag[..])
                );
                let msg_decrypted = match cipher.decrypt(&ctxt, &tag, &nonce, &aad) {
                    Ok(m) => m,
                    Err(_) => {
                        assert!(!valid);
                        msg.clone()
                    }
                };
                assert_eq!(msg, msg_decrypted);
                let msg_decrypted_comb = cipher.decrypt_combined(&ctxt_comb, &nonce, &aad).unwrap();
                assert_eq!(msg, msg_decrypted_comb);
                cipher
                    .decrypt_in_place(in_place_payload.as_mut_slice(), &tag_in_place, &nonce, &aad)
                    .unwrap();
                assert_eq!(msg, in_place_payload);
                *tests_run += 1;
            }
        }
    }
    // Check that we ran all tests.
    println!(
        "Ran {} out of {} tests and skipped {}.",
        tests_run, num_tests, skipped_tests
    );
    assert_eq!(num_tests - skipped_tests, tests_run);
}

#[cfg(feature = "random")]
#[test]
fn key_gen_self_test() {
    fn run(algorithm: Algorithm) {
        let msg = b"Evercrypt rulez";
        let aad = b"associated data";
        let cipher = match Aead::init(algorithm) {
            Ok(c) => c,
            Err(_) => {
                println!("⚠️  Skipping {:?} because it's not available.", algorithm);
                return;
            }
        };
        let key = cipher.key_gen();
        let nonce = cipher.nonce_gen();
        let cipher = cipher.set_key(&key).unwrap();
        let (ctxt, tag) = match cipher.encrypt(msg, &nonce, aad) {
            Ok(v) => v,
            Err(e) => {
                panic!("Encrypt failed unexpectedly {:?}", e);
            }
        };
        let msg_decrypted = match cipher.decrypt(&ctxt, &tag, &nonce, aad) {
            Ok(m) => m,
            Err(_) => msg.to_vec(),
        };
        assert_eq!(msg[..], msg_decrypted[..]);
    }
    if unsafe { hacl_aes_available() } {
        run(Algorithm::Aes128Gcm);
        run(Algorithm::Aes256Gcm);
    } else {
        println!("⚠️  AES NOT AVAILABLE ON THIS PLATFORM!")
    }
    run(Algorithm::Chacha20Poly1305);
}

#[cfg(feature = "hazmat")]
#[test]
fn raw_self_test() {
    use hacl_star::hazmat::{aesgcm, chacha20_poly1305};

    let msg = b"HACL rules";
    let aad = b"associated data";
    let key = b"This key should never be used!!!" as &[u8; 32];
    let iv = b"used more...";

    let mut io = *msg;
    let tag = chacha20_poly1305::encrypt(key, &mut io, *iv, aad);
    assert!(chacha20_poly1305::decrypt(key, &mut io, *iv, aad, &tag).is_ok());
    assert_eq!(&io, msg);

    #[cfg(simd128)]
    {
        let mut io = *msg;
        let tag = chacha20_poly1305::simd128::encrypt(key, &mut io, *iv, aad);
        assert!(chacha20_poly1305::simd128::decrypt(key, &mut io, *iv, aad, &tag).is_ok());
        assert_eq!(&io, msg);
    }

    #[cfg(simd256)]
    {
        let mut io = *msg;
        let tag = chacha20_poly1305::simd256::encrypt(key, &mut io, *iv, aad);
        assert!(chacha20_poly1305::simd256::decrypt(key, &mut io, *iv, aad, &tag).is_ok());
        assert_eq!(&io, msg);
    }

    #[cfg(aes_ni)]
    {
        if aesgcm::hardware_support().is_ok() {
            let mut io = *msg;
            let tag = aesgcm::encrypt_256(key, &mut io, *iv, aad).unwrap();
            assert!(aesgcm::decrypt_256(key, &mut io, *iv, aad, &tag).is_ok());
            assert_eq!(&io, msg);

            let key = b"Never be used!!!" as &[u8; 16];
            let mut io = *msg;
            let tag = aesgcm::encrypt_128(key, &mut io, *iv, aad).unwrap();
            assert!(aesgcm::decrypt_128(key, &mut io, *iv, aad, &tag).is_ok());
            assert_eq!(&io, msg);
        }
    }
}
