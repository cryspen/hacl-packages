mod test_util;

use regex::Regex;
use std::fmt;

use hacl_rust::bignum::Bignum;

use data_encoding::HEXUPPER;
use rand::prelude::SmallRng;
use rand::{RngCore, SeedableRng};

#[test]
fn test_to_from() {
    let trials = 1_000;
    let mut small_rng = SmallRng::seed_from_u64(2038_u64);

    #[derive(Clone)]
    struct Failure {
        in_data: Vec<u8>,
        out_data: Vec<u8>,
        bad_prefix: Option<Vec<u8>>,
        trial: u32,
    }
    impl fmt::Debug for Failure {
        fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt.debug_struct("Failure")
                .field("in", &format_args!("{:?}\n", &self.in_data))
                .field("out", &format_args!("{:?}\n", &self.out_data))
                .field("bad_prefix", &format_args!("{:?}\n", &self.bad_prefix))
                .field("trial", &format_args!("{:?}\n", &self.trial))
                .finish()
        }
    }

    // Less verbose than {:?}
    impl fmt::Display for Failure {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            writeln!(
                f,
                "(in.len: {}, out.len: {}, bad_prefix: {:?}, trial: {})",
                self.in_data.len(),
                self.out_data.len(),
                self.bad_prefix,
                self.trial
            )
        }
    }
    #[derive(Clone)]
    struct FailureVec(Vec<Failure>);

    // There is probably a better way to get FailureVec to inherit
    // Vec methods, but I only need two.
    impl FailureVec {
        fn is_empty(&self) -> bool {
            self.0.is_empty()
        }
        fn len(&self) -> usize {
            self.0.len()
        }
        fn push(&mut self, v: Failure) {
            self.0.push(v)
        }
    }

    impl fmt::Display for FailureVec {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            writeln!(f, "Failures:")?;
            for v in &self.0 {
                write!(f, "\t{}", v)?;
            }
            Ok(())
        }
    }

    let mut failures: FailureVec = FailureVec(Vec::new());

    const TEST_SIZE: usize = Bignum::BN_BYTE_LENGTH - 17;
    // const TEST_SIZE: usize = Bignum::BN_BYTE_LENGTH - 14;

    for trial in 1..=trials {
        let mut dest: [u8; TEST_SIZE] = [0; TEST_SIZE];
        small_rng.fill_bytes(&mut dest);

        let in_data = dest;
        let in_vec = dest.to_vec();

        let bn = Bignum::new(&in_data).unwrap();
        let b_vec = bn.to_vec8().unwrap();

        let mut trimmed_b: Vec<u8> = Vec::new();
        let len_diff = b_vec.len() - in_vec.len();
        let mut should_be_zeros_but_isnt: Vec<u8> = vec![0; len_diff];
        if len_diff > 0 {
            trimmed_b = if let Some(v) = b_vec.strip_prefix(vec![0_u8; len_diff].as_slice()) {
                v.to_vec()
            } else {
                should_be_zeros_but_isnt = b_vec[..len_diff].to_vec();
                b_vec.to_vec()
            }
        }
        let bad_prefix = if should_be_zeros_but_isnt.iter().any(|&x| x != 0_u8) {
            Some(should_be_zeros_but_isnt)
        } else {
            None
        };

        if !trimmed_b.eq(&in_vec) {
            let f = &Failure {
                in_data: in_data.to_vec(),
                out_data: b_vec.clone(),
                bad_prefix,
                trial,
            };
            failures.push(f.clone());
        }
    }

    // If you want the gory details of each failure use the format string
    // with the "{:?}" for failures.
    assert!(
        failures.is_empty(),
        "{}\nThere were {} in-out failure(s) out of {} trials",
        // "{:?}\nThere were {} in-out failure(s) out of {} trials",
        failures,
        failures.len(),
        trials
    );
}

#[test]
#[allow(clippy::neg_cmp_op_on_partial_ord)]
fn test_partial_ord() {
    let trials = 1_000;
    let mut small_rng = SmallRng::seed_from_u64(123_u64);

    // let byte_size = Bignum::BN_BYTE_LENGTH - 256;
    let byte_size = Bignum::BN_BYTE_LENGTH;
    let dest = &mut vec![0; byte_size];
    for trial in 0..trials {
        // we create random a: u128 and a_bn: Bignum
        // which should have same numeric value.
        // And we do the same for b and b_bn.
        small_rng.fill_bytes(dest);
        let a = dest.to_vec();
        let a_bn = Bignum::new(dest).unwrap();

        small_rng.fill_bytes(dest);
        let b = dest.to_vec();
        let b_bn = Bignum::new(dest).unwrap();

        assert!(a_bn == a_bn);
        let i_cmp = a.partial_cmp(&b).unwrap();
        let b_cmp = a_bn.partial_cmp(&b_bn).unwrap();

        assert!(
            i_cmp == b_cmp,
            "i_cmp {:?} != b_cmp {:?} in trial {}",
            i_cmp,
            b_cmp,
            trial
        );
    }
}

#[test]
#[ignore]
// Run
//   cargo test test_memleak -- --ignored
// which may take several minutes.
// That should give you plenty of time to see if processes with names matching
// /test_bignum-*/ grow in memory.
fn test_memleak() {
    let trials = 500_000_u64;
    let mut small_rng = SmallRng::seed_from_u64(123_u64);

    for _ in 0..trials {
        let data = &mut vec![0_u8; 512];
        data.fill(0);

        small_rng.fill_bytes(&mut data[..]);
        let a = Bignum::new(data).unwrap();

        small_rng.fill_bytes(&mut data[..]);
        let b = Bignum::new(data).unwrap();

        let mut true_count = 0;

        if a < b {
            true_count += 1;
        }
        if a > b {
            true_count += 1;
        }
        if a == b {
            true_count += 1;
        }

        assert!(true_count == 1, "We have the wrong number of truths.")
    }
}

#[test]
fn test_constants() {
    let b001 = &Bignum::new(&[0_u8, 0, 1]).unwrap();
    let b101 = &Bignum::new(&[1_u8, 0, 1]).unwrap();
    let b000 = &Bignum::new(&[0_u8, 0, 0]).unwrap();
    let b222 = &Bignum::new(&[2_u8, 2, 2]).unwrap();

    for bn in [&Bignum::ONE, &Bignum::ZERO, b001, b101, b000, b222] {
        assert!(bn == bn, "Something isn't equal to itself")
    }

    struct TestVector<'a> {
        a: &'a Bignum,
        b: &'a Bignum,
        expected: bool,
        name: &'a str,
    }

    let tests = [
        TestVector {
            a: &Bignum::ONE,
            b: &Bignum::ZERO,
            expected: false,
            name: "ONE, ZERO",
        },
        TestVector {
            a: b000,
            b: &Bignum::ZERO,
            expected: true,
            name: "b000, ZERO",
        },
        TestVector {
            a: b001,
            b: &Bignum::ZERO,
            expected: false,
            name: "b001, ZERO",
        },
        TestVector {
            a: b101,
            b: &Bignum::ZERO,
            expected: false,
            name: "b101, ZERO",
        },
        TestVector {
            a: b222,
            b: &Bignum::ZERO,
            expected: false,
            name: "b222, ZERO",
        },
        TestVector {
            a: b000,
            b: &Bignum::ONE,
            expected: false,
            name: "b001, ONE",
        },
        TestVector {
            a: b001,
            b: &Bignum::ONE,
            expected: true,
            name: "b001, ONE",
        },
        TestVector {
            a: b101,
            b: &Bignum::ONE,
            expected: false,
            name: "b101, ONE",
        },
        TestVector {
            a: b222,
            b: &Bignum::ONE,
            expected: false,
            name: "b222, ONE",
        },
        TestVector {
            a: &Bignum::ZERO,
            b: &Bignum::ONE,
            expected: false,
            name: "ZERO, ONE",
        },
        TestVector {
            a: b222,
            b: b101,
            expected: false,
            name: "b222, b101",
        },
    ];

    for t in tests {
        assert!(
            (t.a == t.b) == t.expected,
            "(a,b) Unexpected result for {}",
            t.name
        );
        assert!(
            (t.b == t.a) == t.expected,
            "(b,a) Unexpected result for {}",
            t.name
        );
    }
}

#[test]
fn test_hex() {
    // run enough trials to know that we will get some leading zero bytes.
    let trials = 1_000;

    // really should loop to try at different lengths, including odd ones
    let vec_size = Bignum::BN_BYTE_LENGTH - 129;
    let mut small_rng = SmallRng::seed_from_u64(1138_u64);

    for trial in 1..=trials {
        let mut dest = vec![0_u8; vec_size];
        small_rng.fill_bytes(&mut dest);

        let in_hex = HEXUPPER.encode(&dest);
        let bn = Bignum::from_hex(in_hex.as_str()).unwrap();
        let out_hex = bn.to_hex();

        let in_hex = in_hex.trim_start_matches("00");

        let out_hex = out_hex.trim_start_matches("00");

        assert!(
            in_hex == out_hex,
            "Hexes aren't equal in trial {}\n\tin: {}\n\tout {}",
            trial,
            in_hex,
            out_hex
        );
    }
}

// modpow BIG_B (base), BIG_E (exponent), BIG_M (modulus), BIG_R (result)
// are taken from tests in num_bigint

static BIG_B: &str = "\
                      efac3c0a_0de55551_fee0bfe4_67fa017a_1a898fa1_6ca57cb1\
                      ca9e3248_cacc09a9_b99d6abc_38418d0f_82ae4238_d9a68832\
                      aadec7c1_ac5fed48_7a56a71b_67ac59d5_afb28022_20d9592d\
                      247c4efc_abbd9b75_586088ee_1dc00dc4_232a8e15_6e8191dd\
                      675b6ae0_c80f5164_752940bc_284b7cee_885c1e10_e495345b\
                      8fbe9cfd_e5233fe1_19459d0b_d64be53c_27de5a02_a829976b\
                      33096862_82dad291_bd38b6a9_be396646_ddaf8039_a2573c39\
                      1b14e8bc_2cb53e48_298c047e_d9879e9c_5a521076_f0e27df3\
                      990e1659_d3d8205b_6443ebc0_9918ebee_6764f668_9f2b2be3\
                      b59cbc76_d76d0dfc_d737c3ec_0ccf9c00_ad0554bf_17e776ad\
                      b4edf9cc_6ce540be_76229093_5c53893b";

static BIG_E: &str = "\
                      be0e6ea6_08746133_e0fbc1bf_82dba91e_e2b56231_a81888d2\
                      a833a1fc_f7ff002a_3c486a13_4f420bf3_a5435be9_1a5c8391\
                      774d6e6c_085d8357_b0c97d4d_2bb33f7c_34c68059_f78d2541\
                      eacc8832_426f1816_d3be001e_b69f9242_51c7708e_e10efe98\
                      449c9a4a_b55a0f23_9d797410_515da00d_3ea07970_4478a2ca\
                      c3d5043c_bd9be1b4_6dce479d_4302d344_84a939e6_0ab5ada7\
                      12ae34b2_30cc473c_9f8ee69d_2cac5970_29f5bf18_bc8203e4\
                      f3e895a2_13c94f1e_24c73d77_e517e801_53661fdd_a2ce9e47\
                      a73dd7f8_2f2adb1e_3f136bf7_8ae5f3b8_08730de1_a4eff678\
                      e77a06d0_19a522eb_cbefba2a_9caf7736_b157c5c6_2d192591\
                      17946850_2ddb1822_117b68a0_32f7db88";

// This modulus is the prime from the 2048-bit MODP DH group:
// https://tools.ietf.org/html/rfc3526#section-3
static BIG_M: &str = "\
                      FFFFFFFF_FFFFFFFF_C90FDAA2_2168C234_C4C6628B_80DC1CD1\
                      29024E08_8A67CC74_020BBEA6_3B139B22_514A0879_8E3404DD\
                      EF9519B3_CD3A431B_302B0A6D_F25F1437_4FE1356D_6D51C245\
                      E485B576_625E7EC6_F44C42E9_A637ED6B_0BFF5CB6_F406B7ED\
                      EE386BFB_5A899FA5_AE9F2411_7C4B1FE6_49286651_ECE45B3D\
                      C2007CB8_A163BF05_98DA4836_1C55D39A_69163FA8_FD24CF5F\
                      83655D23_DCA3AD96_1C62F356_208552BB_9ED52907_7096966D\
                      670C354E_4ABC9804_F1746C08_CA18217C_32905E46_2E36CE3B\
                      E39E772C_180E8603_9B2783A2_EC07A28F_B5C55DF0_6F4C52C9\
                      DE2BCBF6_95581718_3995497C_EA956AE5_15D22618_98FA0510\
                      15728E5A_8AACAA68_FFFFFFFF_FFFFFFFF";

static BIG_R: &str = "\
                      a1468311_6e56edc9_7a98228b_5e924776_0dd7836e_caabac13\
                      eda5373b_4752aa65_a1454850_40dc770e_30aa8675_6be7d3a8\
                      9d3085e4_da5155cf_b451ef62_54d0da61_cf2b2c87_f495e096\
                      055309f7_77802bbb_37271ba8_1313f1b5_075c75d1_024b6c77\
                      fdb56f17_b05bce61_e527ebfd_2ee86860_e9907066_edd526e7\
                      93d289bf_6726b293_41b0de24_eff82424_8dfd374b_4ec59542\
                      35ced2b2_6b195c90_10042ffb_8f58ce21_bc10ec42_64fda779\
                      d352d234_3d4eaea6_a86111ad_a37e9555_43ca78ce_2885bed7\
                      5a30d182_f1cf6834_dc5b6e27_1a41ac34_a2e91e11_33363ff0\
                      f88a7b04_900227c9_f6e6d06b_7856b4bb_4e354d61_060db6c8\
                      109c4735_6e7db425_7b5d74c7_0b709508";

#[test]
fn test_modpow_big() {
    let base_hex = BIG_B.to_uppercase().replace('_', "");
    let exp_hex = BIG_E.to_uppercase().replace('_', "");
    let mod_hex = BIG_M.to_uppercase().replace('_', "");
    let expected_hex = BIG_R.to_uppercase().replace('_', "");

    let base = Bignum::from_hex(&base_hex).unwrap();
    let exp = Bignum::from_hex(&exp_hex).unwrap();
    let modulus = Bignum::from_hex(&mod_hex).unwrap();
    let expected = Bignum::from_hex(&expected_hex).unwrap();

    let result = base.modpow(&exp, &modulus).unwrap();

    assert!(result == expected);
}

#[test]
fn test_mont_modpow_big() {
    let base_hex = BIG_B.to_uppercase().replace('_', "");
    let exp_hex = BIG_E.to_uppercase().replace('_', "");
    let mod_hex = BIG_M.to_uppercase().replace('_', "");
    let expected_hex = BIG_R.to_uppercase().replace('_', "");

    let base = Bignum::from_hex(&base_hex).unwrap();
    let exp = Bignum::from_hex(&exp_hex).unwrap();
    let mut modulus = Bignum::from_hex(&mod_hex).unwrap();
    modulus.precomp_mont_ctx().unwrap();
    let expected = Bignum::from_hex(&expected_hex).unwrap();

    let result = base.modpow(&exp, &modulus).unwrap();

    assert!(result == expected);
}

#[test]
fn test_is_odd() {
    let b = BIG_B.to_uppercase().replace('_', "");
    let e = BIG_E.to_uppercase().replace('_', "");
    let m = BIG_M.to_uppercase().replace('_', "");
    let r = BIG_R.to_uppercase().replace('_', "");

    let re_last = Regex::new(r"(..)$").unwrap();
    for t in [b, e, m, r] {
        // There must be better ways to do this without bringing in all the regex machinery
        let caps = re_last.captures(&t).unwrap();
        let last_byte = HEXUPPER.decode(caps[0].as_bytes()).unwrap();
        let pp_byte = last_byte[0].wrapping_add(1);
        let mm_byte = last_byte[0].wrapping_sub(1);

        let t_pp = re_last.replace(&t, HEXUPPER.encode(&[pp_byte]));
        let t_mm = re_last.replace(&t, HEXUPPER.encode(&[mm_byte]));

        let bn = Bignum::from_hex(&t).unwrap();
        let bn_pp = Bignum::from_hex(&t_pp).unwrap();
        let bn_mm = Bignum::from_hex(&t_mm).unwrap();

        let is_odd_t = bn.is_odd().unwrap();
        let is_odd_pp = bn_pp.is_odd().unwrap();
        let is_odd_mm = bn_mm.is_odd().unwrap();

        assert!(is_odd_pp == is_odd_mm);
        assert!(is_odd_t != is_odd_mm);
    }
}
