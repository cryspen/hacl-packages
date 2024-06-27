// jshint esversion: 8

var path = require('path');
var HaclWasm = require(path.resolve(__dirname, './api.js'));
var test_vectors = require(path.resolve(__dirname, './api.json'));
var loader = require(path.resolve(__dirname, './loader.js'));

function buf2hex(buffer) {
  return Array.prototype.map.call(new Uint8Array(buffer), function(x) {
    return ('00' + x.toString(16)).slice(-2);
  }).join('');
}

function hex2buf(hexString) {
  if (hexString === "") {
    return new Uint8Array(0);
  } else {
    return new Uint8Array(hexString.match(/.{2}/g).map(function(byte) {
      return parseInt(byte, 16);
    }));
  }
}

function assert(b, msg) {
  if (!b)
    throw new Error(msg);
}

var preprocessing = function(typ, value) {
  if (typ === "buffer") {
    return hex2buf(value);
  }
  if (typ === "bool") {
    return JSON.parse(value);
  }
  if (typ === "uint32") {
    return JSON.parse(value);
  }
  throw "Unimplemented !";
};

var postprocessing = function(typ, value) {
  if (typ === "buffer") {
    return buf2hex(value);
  }
  if (typ === "bool") {
    return value.toString();
  }
  if (typ === "uint32") {
    return value.toString();
  }
  throw "Unimplemented !";
};

var passTest = function(func_sig, func, msg, t) {
  var args = func_sig.args.filter(function(arg) {
    return (arg.kind === "input") && (arg.tests !== undefined);
  }).map(function(arg) {
    return preprocessing(arg.type, arg.tests[t]);
  });
  var result = func.apply(null, args);
  if (func_sig.return.type !== "void") {
    var expected_result = postprocessing(func_sig.return.type, func_sig.return.tests[t]);
    var result_val = postprocessing(func_sig.return.type, result[0]);
    if (result_val !== expected_result) {
      throw ({
        message: "Wrong return value ! Expecting " + expected_result + ", got " + result_val,
        func: msg,
        index: t,
      });
    }
  }
  func_sig.args.filter(function(arg) {
    return arg.kind === "output";
  }).map(function(arg, i) {
    var result_val;
    var result_name = arg.name;
    if (func_sig.return.type !== "void") {
      result_val = result[i + 1];
    } else {
      if (Array.isArray(result)) {
        result_val = result[i];
      } else {
        result_val = result;
      }
    }
    result_val = postprocessing(arg.type, result_val);
    if (result_val !== arg.tests[t]) {
      throw ({
        message: "Wrong return value for " + result_name + " ! Expecting " + arg.tests[t] + ", got " + result_val,
        func: msg,
        index: t,
      });
    }
  });
  console.log("Test #" + (t + 1) + " passed !");
};

function checkTestVectors(func_sig, func, msg) {
  var number_of_tests = -1;
  var n;
  func_sig.args.map(function(arg) {
    if (arg.tests !== undefined) {
      n = arg.tests.length;
      if (number_of_tests >= 0 && n !== number_of_tests) {
        throw ({
          message: "Inconsistent number of test vectors for arguments",
          func: msg,
        });
      } else {
        number_of_tests = n;
      }
    }
  });
  if (func_sig.return.tests !== undefined) {
    n = func_sig.return.tests.length;
    if (n !== number_of_tests) {
      throw ({
        message: "Inconsistent number of test vectors: " + n + " for return value, " + number_of_tests + " for arguments",
        func: msg,
      });
    }
  }
  console.log("Starting tests for " + msg);
  if (number_of_tests === 0) {
    console.warn("No tests for " + msg + "!");
  }
  for (var t = 0; t < number_of_tests; t++) {
    passTest(func_sig, func, msg, t);
  }
}

// A series of hand-written tests for modules that require API testing that
// cannot be described at the level of a single function.
function testBignum64(Hacl) {
  let a = Hacl.Bignum_64.new_bn_from_bytes_le(hex2buf("4100000000000000"));
  let b = Hacl.Bignum_64.new_bn_from_bytes_le(hex2buf("4200000000000000"));
  let c = Hacl.Bignum_64.new_bn_from_bytes_le(hex2buf("4300000000000000"));
  assert(a instanceof BigUint64Array, "a not of the right return type");
  assert(a.length == 1, "a does not have the right length");
  assert(a[0] == 0x41n, "incorrect layout for a");

  let [ d ] = Hacl.Bignum_64.mul(a, b);
  assert(d instanceof BigUint64Array, "d not of the right return type");
  assert(d.length == 2, "d does not have the right length");
  assert(d[0] == 0x41n*0x42n);
  assert(Hacl.Bignum_64.add_mod(c, a, b)[0][0] == 0x40n);
  assert(Hacl.Bignum_64.sub_mod(c, b, a)[0][0] == 0x01n);
  let [ f ] = Hacl.Bignum_64.sqr(a);
  console.log(c, f);
  assert(Hacl.Bignum_64.mod(c, f)[0][0] == 0x04n);

  let ctx = Hacl.Bignum_64.mont_ctx_init(c);
  let [ e ] = Hacl.Bignum_64.mod_precomp(ctx, d);
  assert(e[0] == 0x02);
  let [ e_bytes ] = Hacl.Bignum_64.bn_to_bytes_le(e);
  assert (e_bytes instanceof Uint8Array);
  assert (e_bytes.length == 8);
  assert (e_bytes[0] == 0x02);

  let [ carry, g ] = Hacl.Bignum_64.add(a, b);
  assert(g[0] == 0x41n+0x42n);
  assert(carry == 0n);

  let [ mask ] = Hacl.Bignum_64.lt_mask(a, b);
  console.log(mask);
  assert(mask == 0xffffffffffffffffn);
}

function testBignumMontgomery64(Hacl) {
  let a = Hacl.Bignum_64.new_bn_from_bytes_le(hex2buf("4100000000000000"));
  let b = Hacl.Bignum_64.new_bn_from_bytes_le(hex2buf("4200000000000000"));
  let n = Hacl.Bignum_64.new_bn_from_bytes_le(hex2buf("4300000000000000"));

  assert(Hacl.Bignum_Montgomery_64.field_modulus_check(n), "prime does not meet conditions");

  let ctx = Hacl.Bignum_Montgomery_64.field_init(n);
  assert(Hacl.Bignum_Montgomery_64.field_get_len(ctx) == 1, "inconsistent length for n");
  let [ aM ] = Hacl.Bignum_Montgomery_64.to_field(ctx, a);
  let [ bM ] = Hacl.Bignum_Montgomery_64.to_field(ctx, b);
  let [ dM ] = Hacl.Bignum_Montgomery_64.mul(ctx, aM, bM);

  let [ d ] = Hacl.Bignum_Montgomery_64.from_field(ctx, dM);
  assert(d[0] == 0x02);

  let eM;

  [ eM ] = Hacl.Bignum_Montgomery_64.add(ctx, aM, bM);
  assert(Hacl.Bignum_Montgomery_64.from_field(ctx, eM)[0][0] == 0x40n);
  [ eM ] = Hacl.Bignum_Montgomery_64.sub(ctx, bM, aM);
  assert(Hacl.Bignum_Montgomery_64.from_field(ctx, eM)[0][0] == 0x01n);
  [ eM ] = Hacl.Bignum_Montgomery_64.sqr(ctx, aM);
  assert(Hacl.Bignum_Montgomery_64.from_field(ctx, eM)[0][0] == 0x04n);

  console.log("a = ", a[0]);
  console.log("aM = ", aM[0]);
  let [ aInvM ] = Hacl.Bignum_Montgomery_64.inverse(ctx, aM);
  console.log("aInvM = ", aInvM[0]);
  console.log("aInv = ", Hacl.Bignum_Montgomery_64.from_field(ctx, aInvM)[0][0]);
  assert(Hacl.Bignum_Montgomery_64.from_field(ctx, aInvM)[0][0] == 0x21n);
}

function testAesGcm128(Hacl) {
  // Basic roundtripping test
  let iv = hex2buf("00000000000000000000000000000000");
  let [ ctx ] = Hacl.AES128_GCM.expand(hex2buf("00000000000000000000000000000000"));
  let plain = (new TextEncoder()).encode("hello", "ascii");
  let aad = (new TextEncoder()).encode("world", "ascii");
  let [ cipher_and_tag ] = Hacl.AES128_GCM.encrypt(ctx, plain, aad, iv);
  let [ success, plain1 ] = Hacl.AES128_GCM.decrypt(ctx, cipher_and_tag, aad, iv);
  assert(success);
  assert((new TextDecoder()).decode(plain1, "ascii") == "hello");

  // Whatever I found... https://datatracker.ietf.org/doc/html/rfc7714#section-16.1.1
  {
    let plain = hex2buf("47616c6c696120657374206f6d6e69732064697669736120696e207061727465732074726573");
    let iv = hex2buf("51753c6580c2726f20718414");
    let key = hex2buf("000102030405060708090a0b0c0d0e0f");
    let aad = hex2buf("8040f17b8041f8d35501a0b2");
    let [ ctx ] = Hacl.AES128_GCM.expand(key);
    let [ cipher_and_tag ] = Hacl.AES128_GCM.encrypt(ctx, plain, aad, iv); 
    console.log(buf2hex(cipher_and_tag));
    console.log("f24de3a3fb34de6cacba861c9d7e4bcabe633bd50d294e6f42a5f47a51c7d19b36de3adf8833899d7f27beb16a9152cf765ee4390cce");
    assert(buf2hex(cipher_and_tag) == "f24de3a3fb34de6cacba861c9d7e4bcabe633bd50d294e6f42a5f47a51c7d19b36de3adf8833899d7f27beb16a9152cf765ee4390cce");
  }
}

// Main test driver
HaclWasm.getInitializedHaclModule().then(function(Hacl) {
  testAesGcm128(Hacl);
  testBignumMontgomery64(Hacl);
  testBignum64(Hacl);

  var tests = [];
  Promise.all(Object.keys(test_vectors).map(function(key_module) {
    Object.keys(test_vectors[key_module]).map(function(key_func) {
      tests.push([test_vectors[key_module][key_func], Hacl[key_module][key_func], key_module + "." + key_func]);
    });
  }));
  for (var i = 0; i < tests.length; i++) {
    checkTestVectors.apply(null, tests[i]);
  }
}).catch(e => {
  if ("func" in e && "index" in e) {
    console.log("Error while running test #", e.index, "for", e.func);
    console.log(e.message);
    process.exit(1);
  } else if ("func" in e) {
    console.log("Error while running tests for", e.func);
    console.log(e.message);
    process.exit(1);
  } else {
    console.log("Unknown error");
    console.log(e);
    process.exit(1);
  }
});
