# OCaml Docs

The OCaml documentation system (odoc) doesn't support documenting multiple versions.
The [ocaml-docs] workflow can be used to generate documentation for all `ocaml-` tags (releases).

## Creating a new release

When creating a new release an `ocaml-` tag with the new version number is created.
(1) After creating the tag the [gh-pages] job must be triggered to create the new, tagged ocaml documentation.
(2) After creating the docs, a link to them must be added to the table in `hacl-ocaml/readme.md`.

[ocaml-docs]: https://github.com/cryspen/hacl-packages/actions/workflows/gh-pages.yml
