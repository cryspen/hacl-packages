# HACL* Javascript bindings

## Structure

This package relies on the WebAssembly output of the KaRaMeL compiler. The following
files need to be in the package directory for the bindings to work :

* all the `.wasm` files corresponding to HACL* modules generated by KaRaMeL;
* `loader.js` and `shell.js`, which are also generated by KaRaMeL

The main file for the bindings is `api.js`. This file reads the API data described
in `api.json` and creates a Javascript object containing functions that call
into the HACL* WebAssembly modules with the correct arguments.

`api_test.js` runs the test vectors for each exposed function to check the  
correctness of the bindings (the WebAssembly code is compiled from verified
code so it should be correct).

## Documentation

Run the file `api_doc.js`. This will create a new file `doc/readable_api.js`.
To produce the JSDoc documentation of the HACL Javascript API, please run

```
jsdoc doc/readable_api.js -d doc/out
```

You can browse the documentation by opening `doc/out/index.html` in your web browser.
