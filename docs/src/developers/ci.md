# Continuous Integration

The HACL Packages project uses [GitHub Actions] as its primary CI/CD system.

When a pull request (PR) or push is made to HACL Packages, the CI automatically runs a series of checks to ensure that all code compiles, all tests pass, and all changes are of a certain quality.
To reduce the amount of computational work, the HACL Packages CI is configured to ignore commits that don't justify a CI run.
For example, the CI will not run on changes of the README.md (and other `*.md` files in the root folder).
If, for whatever reason, you think that a particular commit should not start the CI, consider including `[skip ci]` to your commit message.
(See [Skip pull request and push workflows].)

# Workflows

The CI configuration files are located in the `.github/workflows` folder.
Local actions reused across the HACL Packages CI are in the `.github/actions` folder.

There are multiple workflow files with the following tasks:

* `build.yml` builds and tests HACL Packages on many systems (see below).
* `gh-pages.yml` builds and publishes new versions of this book.
* `new_issue.yml` adds newly created issues to the [HACL Packages project board].
* `ocaml.yml` builds the OCaml bindings for HACL packages.
* `rust.yml` builds the Rust bindings for HACL packages.

## What systems are tested?

GitHub Actions uses the concept of a "job matrix" to fan out a single job description to multiple separate jobs.
This is useful to test a job on different systems, e.g., Linux, macOS, and Windows.
In HACL Packages, and especially in the `build` workflow, we use matrices of the form ...

```yaml
matrix:
  compiler: [ gcc, clang ]
  version: [ 7, 8, ..., 14 ]
  bits: [ 32, 64 ]
  edition: [ c89, "" ]
  exclude:
    - compiler: gcc
      version: 12
    # ...
    # Not available
    - compiler: clang
      version: 14
```

... to cover the following targets:

| Virtual Environment      | Compiler                  | Architecture      |
|--------------------------|---------------------------|-------------------|
| **Tier 1**               |                           |                   |
| Linux (ubuntu-latest)    | gcc (7-11), clang (7-12)  | x86\_64, i686     |
| macOS (macos-latest)     | gcc (9-12), clang (11-14) | x86\_64           |
| Windows (windows-latest) |                           | x86\_64, i686     |
| **Tier 2**               |                           |                   |
| Linux (ubuntu-latest)    | gcc (9-12), clang (11-14) | aarch64           |
| macOS (macos-latest)     | gcc (9-12), clang (11-14) | aarch64           |
| Android (ubuntu-latest)  | gcc (latest)              | aarch64           |
| iOS (macos-latest)       | gcc (9-12), clang (11-14) | aarch64           |
| **Tier 3**               |                           |                   |
| s390x (ubuntu-latest)    | gcc (latest)              | aarch64           |

Furthermore, on Linux, we test different "editions" of the C programming language, i.e., "c89".
On Windows, we run all jobs with and without the `--msvc` flag.

[GitHub Actions]: https://docs.github.com/en/actions
[HACL Packages project board]: https://github.com/orgs/cryspen/projects/1
[Virtual Environment]: https://github.com/actions/virtual-environments
[Skip pull request and push workflows]: https://github.blog/changelog/2021-02-08-github-actions-skip-pull-request-and-push-workflows-with-skip-ci/
