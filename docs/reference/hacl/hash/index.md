# Hash

Hash algorithms in HACL Packages can be used through two APIs: a (simple) one-shot API, and a (more flexible) streaming API.

If you only handle complete messages, i.e., messages that always contain all bytes you want to hash, you can use the one-shot API to easily calculate the digest of that message.
When you are receiving a message chunk-by-chunk, it may be more efficient to use the streaming API.
The streaming API has roughly three phases: init, update, and finish.
You create a context element, call update as often as you need, and then finalize (and cleanup) to obtain a digest.

```{toctree}
:caption: "Algorithms"

blake2/index
sha3
sha2
sha1
md5
```

