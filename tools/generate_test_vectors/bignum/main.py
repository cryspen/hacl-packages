import json
from binascii import hexlify


def make_bytes(x, length=None):
    if not length:
        length = align(x.bit_length(), 8) // 8

    return hexlify(x.to_bytes(length, "big")).decode("ascii")


def align(i, on):
    if i == 0:
        return on

    if i % on == 0:
        return i
    else:
        return i + (on - (i % on))


def gen_candidates(length):
    x = []

    x.append(0)
    x.append(1)
    x.append(2 ** length - 1)

    return x


tests = []

lengths = [256, 4096]

for length in lengths:
    candidates = gen_candidates(length)

    for a in candidates:
        for b in candidates:
            for n in [1337, 2 ** length - 1]:
                tests.append({
                    "length": length,
                    "a": make_bytes(a, length // 8),
                    "b": make_bytes(b, length // 8),
                    "n": make_bytes(n, length // 8),
                    "add": make_bytes((a + b) % (2 ** length), length // 8),
                    "add_mod": make_bytes((a + b) % n, length // 8),
                    "add_carry": (a + b) // (2 ** length),
                    "sub": make_bytes((a - b) % (2 ** length), length // 8),
                    "sub_mod": make_bytes((a - b) % n, length // 8),
                    "sub_carry": 1 if a < b else 0,
                    "sqr": make_bytes(a * a, (length * 2) // 8),
                    "exp_mod": make_bytes(pow(a, b, n), length // 8),
                })

print(json.dumps(tests, indent=2))
