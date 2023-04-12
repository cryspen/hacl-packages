# JavaScript

## Building, testing, and installing the `hacl-wasm` npm package

The package directory can be put together using a script:

```bash
./npm.sh
cd npm
```

Tests can be run with:

```bash
node api_test.js
```

The package can be installed with:

```bash
npm install
```


## Publishing a new version of the `hacl-wasm` package to npm

Assuming all the steps above ran successfully, a new version of the package
can be published on npm. First, update the version number in `package.json`
and propagate it using `npm install`.

A tag `js-vX.X.X` should be created with the new version of the package.

The package can then be published with:

```bash
npm publish
```

This last step requires having logged in to npm and having the correct
access rights.
