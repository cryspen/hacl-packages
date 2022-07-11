mod test_util;
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
