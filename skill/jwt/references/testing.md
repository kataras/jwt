# Testing

## No external service required

Unlike a library that talks to a database, `github.com/kataras/jwt` is pure computation (crypto,
encoding, in-memory state) except for the explicitly-network-facing pieces (`FetchJWKS`,
`FetchAWSCognitoPublicKeys`). `go test ./...` at the repository root runs everywhere, with no
setup, and is fast. There is no equivalent of pg's `pgtest`/`PG_CONNSTRING` here; nothing to skip,
nothing to point at a running service for the ordinary test suite.

CI (`.github/workflows/ci.yml`) runs, on Go 1.26.x, `go vet ./...`, then `go test -v --race
./...`, then a second full run with `go test --race -tags safe ./...`. Match that locally before
calling a change to this package done:

```sh
go vet ./...
go test -race ./...
go test -race -tags safe ./...
```

## `jwt.Clock` for deterministic time-based tests

Every expiry, not-before, issued-at, and `MaxAge`/`Leeway`/`Skew` calculation reads the
package-level `jwt.Clock` variable (default `time.Now`). Override it to test expiry logic without
sleeping:

```go
fixed := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
old := jwt.Clock
jwt.Clock = func() time.Time { return fixed }
defer func() { jwt.Clock = old }() // restore; it is a package-level global

token, _ := jwt.Sign(jwt.HS256, key, claims, jwt.MaxAge(time.Minute))

jwt.Clock = func() time.Time { return fixed.Add(2 * time.Minute) }
_, err := jwt.Verify(jwt.HS256, key, token) // err is jwt.ErrExpired
```

Because `Clock` is a shared package-level variable, tests that set it and run in parallel
(`t.Parallel()`) with other tests reading it will race with each other; do not parallelize a test
that overrides `Clock` alongside one that does not restore it deterministically. Always restore
the original in a `defer`, including on the failure path.

`Blocklist` has its own clock, independent of the package-level variable (falling back to it when
never set); call `(*jwt.Blocklist).SetClock` on the blocklist under test instead of touching the
global if you only need to control that one blocklist's notion of "now". It is a method rather
than a field because garbage collection reads the clock from a goroutine started inside
`NewBlocklist`, so a plain field could not be assigned without racing that goroutine. `SetClock`
is safe to call at any time, including while a sweep is running, and `nil` restores the
package-level `Clock`.

`jwt.KeySet` (`NewRemoteKeySet`/`NewCognitoKeySet`) starts a background refresh goroutine the same
way `Blocklist` starts a GC goroutine: call `(*KeySet).Close()` (typically `defer`red right after
construction) in every test that builds one, or it leaks a ticker and a goroutine per test. For a
test that should not hit the network at all, use `WithHTTPClient` with a stub `HTTPClient`
(anything with a `Get(string) (*http.Response, error)` method) rather than pointing `KeySet` at a
real URL.

## The `-tags safe` build

`jwt.BytesToString` has two implementations selected by a build tag: the default uses `unsafe` for
a zero-allocation conversion (the returned string aliases the input slice's memory; do not mutate
the slice afterward), and `-tags safe` swaps in a plain, allocating `string(b)` conversion. Both
must compile and pass identically, which is why CI runs the suite under both. If you use
`BytesToString` yourself and care about behavior under `-tags safe`, add it to your own build/test
matrix too; ordinary `go test ./...` alone only exercises the default (`unsafe`) build.

## `_examples/` and `_benchmarks/` are separate modules

Both directories carry their own `go.mod` (with a `replace` pointing at the parent module) and are
excluded from the root module's build and from CI. `go test ./...`/`go build ./...` at the
repository root does not touch them, `go mod tidy` at the root does not affect their dependencies,
and a compile failure in either is not something a root-level change is expected to have caused
(though it is worth checking manually if you changed a public signature they use). Treat
`_examples/*/main.go` as read-only reference material for real, intended usage; several are
referenced directly from `api-map.md` and `keys-and-jwks.md` in this skill.

## Golden tests, and no `Example`-test harness

`golden_test.go` pins the exact bytes this package emits today (headers per algorithm, whole
tokens for the algorithms with deterministic signatures) against `testdata/golden.json`, precisely
so a refactor that quietly changes generated output cannot pass unnoticed. It deliberately records
current behavior, wrong-but-scheduled-to-be-fixed included, rather than asserting what "should"
happen. If you are modifying the library itself and a golden test fails, treat that as a real
behavior change to review, not stale expected data to regenerate away; regenerating (`go test -run
TestGolden -update`) is a maintainer action for a genuine, reviewed change, not something to do
just to make a red test green.

This package has no `func Example*` tests (Go's executable-documentation test form). Doc comments,
including everything in `doc.go`, are prose only: not compiled, not run, not verified by CI. Do
not treat a code sample inside a doc comment as confirmation that an API works as shown; find the
corresponding `_test.go` file (the golden tests included) or read the implementation instead.
(This skill's own reference documents were written the same way: from the `.go` source, not from
doc comments.)

## Where to look for a specific edge case

Test file names are a reasonably reliable map of what they cover; grep before guessing:

| File | Covers |
| --- | --- |
| `bounds_test.go` | `MaxTokenSize` enforcement |
| `golden_test.go` | Exact-byte output for headers (every algorithm) and whole tokens (the deterministic algorithms), against `testdata/golden.json` |
| `naming_test.go` | Header byte-layout edge cases (field order, missing `"typ"`) |
| `claims_time_test.go`, `leeway_test.go` | `nbf`/`iat`/`exp` validation, including the zero-vs-negative distinction |
| `enrich_test.go`, `enrich_security_test.go` | `Enrich`/`UnverifiedToken.Enrich`/`Keys.EnrichToken`, including the algorithm/`kid`-pinning behavior |
| `blocklist_test.go`, `blocklist_revocation_test.go` | `Blocklist` GC and key-derivation behavior |
| `keyset_test.go` | `KeySet` (`NewRemoteKeySet`/`NewCognitoKeySet`): refresh-on-unknown-`kid`, rate limiting, and concurrent-use safety |
| `jwk_fetch_test.go` | `FetchJWKS` error paths and size/scheme limits |
| `input_test.go` | Malformed-token handling |

`Keys`/`Register`/`KeysConfiguration` (`kid_keys.go`) have no single dedicated test file; their
behavior is exercised across `naming_test.go`, `golden_test.go`, and `enrich_security_test.go`
alongside whatever else each of those files is primarily testing.

## Test key hygiene

Nothing in the library enforces HMAC key length or RSA key size at either sign or verify time (see
`security.md`). A test using a short, memorable HMAC secret will not fail because of it; do not
copy that secret, or that pattern, into production code. `_testfiles/` holds the RSA/ECDSA/EdDSA
PEM key pairs the test suite and `_examples/` use; they are test fixtures, publicly committed, and
must never be reused as real keys.
