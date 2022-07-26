# A place to generate some test data for bignum

from ast import Num
from random import randint

from numpy import append

BIT_SIZE: int = 4096

top: int = pow(2, BIT_SIZE) - 1


def rand() -> int:
    return randint(0, top)


def rand_hex() -> tuple[int, str]:
    r: int = randint(0, top)
    return r, u_hex(r)


def u_hex(n: int) -> str:
    s = f'{n:X}'
    if len(s) % 2 == 1:
        s = '0' + s  # do I have python scoping right?
    return s


class ReductionTriple:
    def __init__(self, num: int, modulus: int):
        self.num: int = num
        self.modulus: int = modulus

        if self.modulus % 2 == 0:
            self.modulus += 1
        self.result: int = num % modulus

    def __str__(self) -> str:
        s = f'''\tTestVector{{
            a: "{u_hex(self.num)}",
            m: "{u_hex(self.modulus)}",
            expected: "{u_hex(self.result)}",
        }},
        '''

        return s


def create_rand_reductions(count: int) -> list[ReductionTriple]:
    tests: list[ReductionTriple] = []
    for _ in range(count):
        a = rand()
        m = rand()
        triple = ReductionTriple(a, m)
        tests.append(triple)

    return tests


def main():
    r_list = create_rand_reductions(10)
    for r in r_list:
        print(r, end='')


if __name__ == "__main__":
    main()
