# Benchmarks

HACL Packages provides a set of benchmarks that serves two purposes: To detect regressions, and to see how HACL Packages compares to other cryptographic libraries. Although the benchmarks give us an idea about HACL Package's performance, they should not be overly relied on.

All benchmarks are in the `benchmarks` folder and are registered through `config/config.json` in `mach`. To build the benchmarks, run ...

```sh
./mach build --benchmarks --release
```

Then, to run the benchmarks, execute ...

```sh
./mach benchmark
```

Note that it is also possible to compare two benchmark runs, e.g., to test for regressions. For this, you need to have a separate hacl-packages checkout, and execute ...

```sh
./mach benchmark --compare <path_to_other_hacl_packages_checkout>
```

Note that you need to build the benchmarks in the other checkout, too. But `mach` will remind you about that.

## Contributing to the benchmarks

We use the [Google Benchmark] framework to define and run all benchmarks and it is generally useful to consult the [User Guide] while working on the benchmarks. Although Google Benchmark helps a lot, writing benchmarks remains a delicate task. Thus, we collected some rules of thumb to apply during benchmarking:

* Benchmark against a specific usecase, i.e., "Alice obtains a serialized message, and public key, and needs to verify it.". This way, it is clear with what input the benchmarks start. If you provide a comparison, e.g., against OpenSSL, make sure that both libraries "do the same thing", i.e., that we don't measure setup/cleanup routines in one library but skip in the other.
* Use fixed inputs. During benchmarking, it is okay to always use the same message, same key material, etc. If you feel that we need to randomize this, do it deterministic, e.g., by precomputing random values.
* Do not use `assert`. Asserts are stripped in release builds and may even lead to broken benchmarks because the code you intended to run is optimized out.
* Do not test. Benchmarks are benchmarks. Tests are tests. If you feel that a benchmark would benefit from a sanity check, you can use `state.SkipWithError()`. Note, however, that you probably want to avoid this in the benchmark loop. Also, in comparisons, when you check the value of one library, make sure to also check in the other library.
* Don't repeat yourself. It is tempting to copy&paste benchmark code. We've been there and it doesn't turn out great. Try to make good use of Google Benchmark features to deduplicate code.

[google benchmark]: https://github.com/google/benchmark
[user guide]: https://github.com/google/benchmark/blob/main/docs/user_guide.md
