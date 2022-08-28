import json
from binascii import hexlify


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x % m


def make_bytes(num, length):
    return hexlify(num.to_bytes(length, "big")).decode("ascii")


def do(xs, ns, length, limbs32, limbs64):
    tests = []

    for n in ns:
        for a in xs:
            for b in xs:
                tests.append({
                    "limbs32": limbs32,
                    "limbs64": limbs64,
                    "a": make_bytes(a, length),
                    "b": make_bytes(b, length),
                    "bBits": b.bit_length(),
                    "n": make_bytes(n, length),
                    "add": make_bytes(((a + b) % n), length),
                    "sub": make_bytes(((a - b) % n), length),
                    "mul": make_bytes(((a * b) % n), length),
                    "sqr": make_bytes(pow(a, 2, n), length),
                    "exp": make_bytes(pow(a, b, n), length),
                    "inv": make_bytes(modinv(a, n), length),
                })

    return tests


xs1 = [1, 2, 3, 4, 5, 6]
ns1 = [7]

xs2 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
ns2 = [13]

xs8 = [1, 2, 8, 245, 255, 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff - 128,
       0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff - 1,
       0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff]
ns8 = [(2 ** 255) - 19]

tests = []
tests.extend(do(xs1, ns1, 4, 1, 1))
tests.extend(do(xs2, ns2, 4, 1, 1))
tests.extend(do(xs8, ns8, 32, 8, 4))

print(json.dumps(tests, indent=2))
