# Benchmarks

NetTrap uses Criterion benchmarks with fixed synthetic inputs. Run the same
suite as CI from the workspace root:

```bash
cargo bench --no-fail-fast
```

The heavy quality-gate workflow uploads `target/criterion` as
`benchmark-results-<commit SHA>`. The artifact includes Criterion samples,
reports, and `environment.txt` with the exact Rust, Cargo, kernel, and
architecture context.

Compare results only between the same target architecture and comparable
runner class. Cross-hardware timing is not a regression signal. The current
suite measures HTTP GET, content-length POST, and chunked-request parsing with
byte-for-byte fixtures defined in
`crates/nettrap-proto-http/benches/http_parser.rs`.

Add a benchmark only for a measured hot path and keep its fixture deterministic.
Record substantial performance investigations under `.planning/profiling/` as
required by the repository guidelines.
