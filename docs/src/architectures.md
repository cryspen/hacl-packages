# Architectures

The HACL C library has different optimization for different platforms.

|            | x86 | x86-64             | Arm32 | Arm64 | s390x |
| ---------- | --- | ------------------ | ----- | ----- | ----- |
| Portable C | ✓   | ✓                  | ✓     | ✓     | ✓     |
| Vec128     | -   | SSE2, SSE3, SSE4.1 | -     | NEON  | z14   |
| Vec256     | -   | AVX, AVX2          | -     | -     | -     |
