# Hash

Hash algorithms in HACL Packages can be used through two APIs: a (simple) **One-shot API**, and a (more flexible) **Streaming API**.

Note: HACL Packages supports MD5 but does not document it here because it should not be used.

**One-shot API**

If you want to hash a complete messages, i.e., can provide a slice of memory that already contains all the bytes you want to hash, you can use the one-shot API and `hash` to easily calculate the digest of that message.

**Streaming API**

If you need to provide a message chunk-by-chunk, e.g., because you read the message from network or similar, it could be more appropriate to use the streaming API.

The streaming API has roughly three phases: init, update, and finish.
Typically, you create a state element by using `init`, call `update` as often as needed, and then call `finish` to obtain the final digest.
Finally, you `free` the state element.

**Streaming API (with intermediate digests)**

It is also possible to obtain all intermediate digests by calling `finish` more than once.
You can call `update("Hello, ")`, and `finish` to obtain the hash of `"Hello, "`.
Then you can call `update("World!")`, and `finish` *again* to obtain the hash of `"Hello, World!"`.
You only need to call `init` and `free` once to obtain both digests.

```{toctree}
:caption: "Algorithms"

blake2/index
sha3
sha2
sha1
```

