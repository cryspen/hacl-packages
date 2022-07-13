mod test_util;
use hex;
use test_util::*;

use hacl_rust::bignum::{Bignum, Error};

fn bn_from_u64(n: u64) -> Bignum {
    let b = n.to_be_bytes();
    let v = b.to_vec();
    let bn: Result<Bignum, Error> = Bignum::new(v);
    bn.unwrap()
}

#[test]
#[allow(clippy::neg_cmp_op_on_partial_ord)]
fn test_partial_ord() {
    let v2038_bn = bn_from_u64(2038_u64);
    let v1337_bn = bn_from_u64(1337_u64);

    assert!(v1337_bn < v2038_bn, "1337 should be lt 2038");
    assert!(v1337_bn != v2038_bn, "1337 should be not equal to 2038");
    assert!(!(v1337_bn > v2038_bn), "1337 should not be gt 2038");
    assert!(!(v1337_bn == v2038_bn), "1337 should not be equal to 2038");
}

use rand::prelude::SmallRng;
use rand::{RngCore, SeedableRng};

#[test]
#[ignore]
// Run
//   cargo test test_memleak -- --ignored
// which may take several minutes.
// That should give you plenty of time to see if processes with names matching
// /test_bignum-*/ grow in memory.
fn test_memleak() {
    let trials = 5_000_000_u64;
    let mut small_rng = SmallRng::seed_from_u64(123_u64);

    for _ in 0..trials {
        let data = &mut vec![0_u8; 512];
        data.fill(0);

        small_rng.fill_bytes(&mut data[..]);
        let a = Bignum::new(data.to_vec()).unwrap();

        small_rng.fill_bytes(&mut data[..]);
        let b = Bignum::new(data.to_vec()).unwrap();

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
