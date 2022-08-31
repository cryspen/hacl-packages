# AEADs

`hacl-rust` implements three AEADs

```rust,noplayground
{{#include ../../../../rust/src/aead.rs:aead_algorithm}}
```

There are two different ways of using AEADs.

## Single shot API

The entrypoint for many people will be the single shot API that takes all
necessary arguments in one function call.

```rust,noplayground
{{#include ../../../../rust/tests/aead-book.rs:single_shot_encrypt}}
```

```rust,noplayground
{{#include ../../../../rust/tests/aead-book.rs:single_shot_decrypt}}
```

## Stateful API

In many cases a key is used multiple times though.
For this case there's a stateful API.

```rust,noplayground
{{#include ../../../../rust/tests/aead-book.rs:stateful_cipher}}
```

```rust,noplayground
{{#include ../../../../rust/tests/aead-book.rs:stateful_encrypt}}
```

## In-place APIs

The API also allows to use in-place encryption and decryption, which avoids
having to allocate memory for the result.

```rust,noplayground
{{#include ../../../../rust/src/aead.rs:aead_encrypt_in_place}}
```

```rust,noplayground
{{#include ../../../../rust/src/aead.rs:aead_decrypt_in_place}}
```

## Combined APIs

In many protocols such as TLS the tag is appended to the cipher text.
To avoid unnecessary copy operations there's an API doing this for you.

```rust,noplayground
{{#include ../../../../rust/src/aead.rs:aead_encrypt_combined}}
```

```rust,noplayground
{{#include ../../../../rust/src/aead.rs:aead_decrypt_combined}}
```
