CC=clang-16
CFLAGS=-march=native -mtune=native -O3 -Wall -Wextra -std=c89 -pedantic -Wno-long-long
BLAKEBINS=blake2s-ref.a blake2b-ref.a

all:$(BLAKEBINS)

blake2s-ref.a:	blake2s-ref.c blake2.h blake2-impl.h
		$(CC) -shared blake2s-ref.c -o $@ $(CFLAGS)

blake2b-ref.a:	blake2b-ref.c blake2.h blake2-impl.h
		$(CC) -shared blake2b-ref.c -o $@ $(CFLAGS)

clean:
		rm -rf *.o $(BLAKEBINS)
