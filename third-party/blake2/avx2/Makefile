CC=clang-16
CFLAGS=-march=native -mtune=native -O3 -Wall -Wextra -std=c89 -pedantic -Wno-long-long
BLAKEBINS=blake2b1.a blake2b2.a blake2b3.a

all:$(BLAKEBINS)

blake2b1.a:	blake2b.c blake2b-round.h blake2b-load-neon.h
		$(CC) -shared blake2b.c -DPERMUTE_WITH_NOTHING -o $@ $(CFLAGS)
blake2b2.a:	blake2b.c blake2b-round.h blake2b-load-neon.h
		$(CC) -shared blake2b.c -DPERMUTE_WITH_SHUFFLES -o $@ $(CFLAGS)
blake2b3.a:	blake2b.c blake2b-round.h blake2b-load-neon.h
		$(CC) -shared blake2b.c -DPERMUTE_WITH_GATHER -o $@ $(CFLAGS)
clean:
		rm -rf *.o $(BLAKEBINS)
