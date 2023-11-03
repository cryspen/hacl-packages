CC=clang-16
CFLAGS=-march=native -mtune=native -O3 -Wall -Wextra -std=c89 -pedantic -Wno-long-long
BLAKEBINS=blake2s.a blake2b.a blake2s-neon.a blake2b-neon.a

all:$(BLAKEBINS)

blake2s.a:	blake2s.c blake2s-round.h blake2s-load-neon.h
		$(CC) -shared blake2s.c -o $@ $(CFLAGS)

blake2b.a:	blake2b.c blake2b-round.h blake2b-load-neon.h
		$(CC) -shared blake2b.c -o $@ $(CFLAGS)

blake2s-neon.a:	blake2s-neon.c blake2s-round.h blake2s-load-neon.h
		$(CC) -shared blake2s-neon.c -o $@ $(CFLAGS)

blake2b-neon.a:	blake2b-neon.c blake2b-round.h blake2b-load-neon.h
		$(CC) -shared blake2b-neon.c -o $@ $(CFLAGS)

clean:
		rm -rf *.o $(BLAKEBINS)
