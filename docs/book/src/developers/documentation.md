# Documentation

The HACL Packages documentation consists of a high-level **HACL Packages Book** (that you are reading right now) and (multiple) technical references describing the provided programming language bindings.

The book aims to give a high-level overview of the HACL Packages project. It describes the build process, the infrastructure (CI/CD), and how we want to work with each other. Notably, we also need to document the documentation system itself, which is what the next section is about.

## Documentation Infrastructure (C)

### Building the documentation

The HACL Packages can be built with `mach` ...

```sh
./mach doc
```

... and the tool will tell you what to install and how to view the documentation.

### Contributing to the documentation

The documentation system uses [Doxygen], [Sphinx], and [Breathe] to document the [HACL\*] C API.

The build process is roughly as follows: First, `mach` runs Doxygen to generate an XML representation of the HACL\* library. Then, Sphinx uses the Breathe plugin to extract and create reference documentation in all places in the markdown files that reference HACL\* C functions or types.

A directive to a C function in the HACL\* library may look like this:

````md
```{doxygenfunction} Hacl_Hash_SHA2_hash_256
```
````

Here, we used the `doxygenfunction` directive to instruct Sphinx to generate a documentation block for the `Hacl_Hash_SHA2_hash_256` function. This will always create a stub of the function and, possibly, documentation if available.

Referencing functions (and types) on a fine-grained basis allows us to "cluster" API entry points and makes the documentation easier to understand. Thus, we also use tabs and sections to improve readability.
Note that you can wrap code blocks by using more backticks:

``````md
`````{tabs} A tab environment
````{tab} First tab
```{doxygenfunction} Hacl_Hash_SHA2_hash_256
```
````
````{tab} Second tab
```{doxygenfunction} Hacl_Hash_SHA2_hash_512
```
````
``````

### Adding missing documentation

Generally, the reference documentation, i.e., the description of a specific type or function, should leverage as much existing documentation as possible from the [HACL\*] project.
Suppose a particular function (or type) lacks documentation. In that case, we can proceed as follows: Either we provide ad-hoc documentation by opening a PR on HACL Packages and writing it just below the referenced stub, or we provide documentation by opening a PR in the [HACL\*] project updating HACL Packages afterward.

Generally, we do want to upstream as much documentation as possible. Still, the first variant can be a stepping stone toward variant two. Furthermore, it could make sense to provide information in HACL Packages that don't fit in HACL\*.

[hacl\*]: https://github.com/hacl-star/hacl-star
[doxygen]: https://www.doxygen.nl/
[breathe]: https://breathe.readthedocs.io/en/latest/
[sphinx]: https://www.sphinx-doc.org/en/master/
[breathe directives]: https://breathe.readthedocs.io/en/latest/directives.html#directives
