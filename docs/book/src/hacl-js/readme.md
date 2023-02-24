# JavaScript Package

HACL* is compiled to WebAssembly via the WASM backend of Karamel (see the
Oakland'19 paper for details). We offer an idiomatic JavaScript API on top of
HACL-WASM so that clients do not have to be aware of the Karamel memory layout,
calling convention, etc. This latter API is available as a
[Node.js package](https://www.npmjs.com/package/hacl-wasm).

Please note that the API is asynchronous (it uses promises).
Here is a small example of how to use the library (with Node.js):

```
  var hacl = require("hacl-wasm");
  hacl.Curve25519.ecdh(new Uint8Array(32), new Uint8Array(32)).then(function (result) {
    // Here result contains an Uint8Array of size 32 with the DH exchange result
  });
```

Please check out the [latest documentation](../js/main/index.html) 📚
