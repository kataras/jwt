# Chapter 13: Testing

Code that signs and verifies tokens is hard to test badly and easy to test uselessly. The
useless version stands up a real identity provider, waits for a real clock, and passes
because the network happened to be up. This chapter is about the other kind: tests that run
in milliseconds, fail for one reason, and keep failing until somebody fixes the thing they
were written about. This package's own suite works that way, so most of what follows
describes code you can read in the repository.

## Table of Contents

- [The suite that never opens a socket](#the-suite-that-never-opens-a-socket)
- [Controlling time](#controlling-time)
- [Keys for tests](#keys-for-tests)
- [Faking the network](#faking-the-network)
- [A fake that rotates](#a-fake-that-rotates)
- [Golden tests](#golden-tests)
- [Table-driven tests for the error paths](#table-driven-tests-for-the-error-paths)
- [Testing that something is refused](#testing-that-something-is-refused)
- [Replacing Marshal and Unmarshal](#replacing-marshal-and-unmarshal)
- [The race detector](#the-race-detector)
- [Summary](#summary)
- [Further Reading](#further-reading)

## The suite that never opens a socket

This package has 112 test functions across 28 files. Not one of them opens a socket. There
is no `httptest.NewServer`, no `net.Listen`, no `http.Get`. The whole suite finishes in
about four seconds. That is not an accident of scope: half the package fetches key material
over HTTPS, refreshes it on a timer, and refetches it when a token names a key identifier
nobody has seen. All of that is tested, and none of it touches the network.

Three seams make it possible, and you get all three: `Clock` for the current time,
`ReadFile` for PEM files on disk, and the `HTTPClient` interface for the JWKS fetch. Two of
them are package-level variables. That is the trade-off. A seam you can reach without
threading a parameter through six call sites is also a seam any other test in the same
binary can reach at the same moment.

## Controlling time

Every time-based check in the package reads one variable, declared as `var Clock =
time.Now`. Replace it and `exp`, `nbf` and `iat` are all evaluated against whatever you
return. Save the old value, restore it from `t.Cleanup` so the restore survives a failure
partway through:

```go
// at moves the package clock to a fixed instant and puts it back afterwards.
func at(t *testing.T, when time.Time) {
	t.Helper()

	previous := jwt.Clock
	t.Cleanup(func() { jwt.Clock = previous })
	jwt.Clock = func() time.Time { return when }
}
```

Call `at` once before signing and again with a later instant before verifying, and the
expiry rule is under test rather than the scheduler. The package's own tests use this
shape: `sign_test.go` copies the old value into `prevClock` and restores it from
`t.Cleanup`, and `claims_test.go` does the same with a `defer`.

**`Clock` is read without a lock.** Every call to `Verify` reads it and your assignment
writes it, which is a data race in the formal sense: the detector reports it and the
compiler is entitled to do something surprising with it. So no test touching `Clock` may
call `t.Parallel()`, and neither may anything running beside it. Go gives each package its
own test binary, so a swap in your package cannot reach another package's tests, but within
one package the whole file set shares the variable.

Where you can, skip the swap: a test that wants an expired token needs only an `exp` in the
past, and that version is parallel-safe. Reach for the clock when the code under test
computes a timestamp rather than reads one, which is what `MaxAge`, `SignPair` and the
leeway validators do.

`Blocklist` is the counter-example: its clock is per-instance, so two blocklists in two
parallel tests hold two clocks and never notice each other. `NewBlocklist(0)` starts one with
no background collector, `b.SetClock` moves it an hour forward, and `b.GC()` then collects
exactly the entries that expired in between. Prefer that shape in your own code.

`SetClock` is a method rather than a field for a reason worth copying. Automatic garbage
collection reads the clock from a goroutine the constructor starts before it returns, so an
exported field had no safe moment left for the assignment. The library shipped that field
once and its own suite tripped `-race` on it. Any struct that hands a caller a knob and then
reads it from a goroutine of its own has the same problem.

## Keys for tests

The repository keeps a fixed set of key pairs under `_testfiles/`: RSA, RSA-PSS, ECDSA and
Ed25519 in PEM, an HMAC secret, and one deliberately corrupt PEM for the parse failures.
They load through helpers that panic rather than return an error, because a missing fixture
is a broken checkout rather than a condition a test should branch on:

```go
func MustLoadRSA(privateKeyFilename, publicKeyFilename string) (*rsa.PrivateKey, *rsa.PublicKey)
func MustLoadECDSA(privateKeyFilename, publicKeyFilename string) (*ecdsa.PrivateKey, *ecdsa.PublicKey)
func MustLoadEdDSA(privateKeyFilename, publicKeyFilename string) (ed25519.PrivateKey, ed25519.PublicKey)
```

For HMAC there is nothing to load. `func MustGenerateRandom(n int) []byte` gives you a
secret: 32 bytes for HS256, 48 for HS384, 64 for HS512, at 345 nanoseconds per call. For a
fresh Ed25519 pair as PEM there is `func GenerateEdDSA() (publicPEM []byte, privatePEM
[]byte, err error)`. Note the return order. Public comes first, the opposite of the
convention nearly every other key API in Go follows, and a test that binds them the wrong
way round fails at the signing call rather than at the assignment. That pair took about 20
microseconds to generate, so one per test is fine.

Do not do the same with RSA. Generating a 2048-bit key took between 73 and 115 milliseconds
across three runs of thirty on the machine named in Chapter 14. Thirty tests each generating
one add three seconds to a suite that otherwise runs in four, and because key generation is
a search for primes the cost is random as well as large. Load
`_testfiles/rsa_private_key.pem` instead.

**The keys in `_testfiles/` are published.** They sit in a public repository and anybody can
read them. They exist to make signatures reproducible, which is the opposite of what a
signing key is normally for. Never let one reach a file a deployment might read.

## Faking the network

The JWKS fetch takes its client as `type HTTPClient interface { Get(string)
(*http.Response, error) }`, one method, and it is the method `*http.Client` already has.
That is the whole reason the interface exists: `func FetchJWKS(client HTTPClient, rawURL
string) (*JWKS, error)` and `func WithHTTPClient(client HTTPClient) RemoteKeySetOption` can
both be handed something that is not a client at all. Here is a fake that answers from a
canned string and remembers what it was asked for, modelled on `recordingClient` in
`jwk_fetch_test.go`:

```go
type recordingClient struct {
	status    int
	body      string
	requested []string
}

func (c *recordingClient) Get(url string) (*http.Response, error) {
	c.requested = append(c.requested, url)

	status := c.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{StatusCode: status,
		Body: io.NopCloser(strings.NewReader(c.body))}, nil
}
```

The `requested` slice is what makes it more than a stub. A test can loop over
`http://auth.example.com/keys`, `ftp://...` and `file:///etc/passwd`, check that every
`FetchJWKS` call returns an error, and then assert `len(client.requested) == 0`. That last
line is the interesting one: it proves the scheme was refused before a request went out
rather than after.

The same fake covers cases a real server makes awkward. A body larger than `MaxJWKSSize`,
which is 1 MB, is one `strings.Repeat` away, and a 401 whose body carries a forged log line
is a string literal.

## A fake that rotates

Rotation is the case a canned answer cannot test, because the point of rotation is that the
answer changes. `keyset_test.go` has a client that can be reconfigured mid-test and counts
its calls:

```go
type rotatingClient struct {
	mu      sync.Mutex
	body    string
	fails   bool
	fetches atomic.Int64
}

func (c *rotatingClient) Get(url string) (*http.Response, error) {
	c.fetches.Add(1)

	c.mu.Lock()
	body, fails := c.body, c.fails
	c.mu.Unlock()

	if fails {
		return &http.Response{StatusCode: http.StatusInternalServerError,
			Body: io.NopCloser(strings.NewReader("upstream is unwell"))}, nil
	}
	return &http.Response{StatusCode: http.StatusOK,
		Body: io.NopCloser(strings.NewReader(body))}, nil
}

// serve replaces the answer, under the same lock Get reads it through.
func (c *rotatingClient) serve(body string, fails bool) { /* ... */ }
```

The mutex is not decoration. `KeySet` refreshes from its own goroutine, so the fake really
is called concurrently, and the counter is an `atomic.Int64` for the same reason. With it, a
rotation becomes deterministic:

```go
client := &rotatingClient{}
client.serve(jwksFor(t, "key-one"), false)

keySet, err := jwt.NewRemoteKeySet("https://auth.example.com/keys",
	jwt.WithHTTPClient(client),
	jwt.WithRefreshInterval(0),    // no background timer; the test drives it
	jwt.WithMinRefreshInterval(0), // and no rate limit, so the refetch is immediate
)
// verify under key-one, assert one fetch, then serve both kids and verify under key-two
```

Setting both intervals to zero removes the timing dependency. The background refresh never
fires and the rate limit on the unknown-key refetch is off, so every fetch in the count is
one the code chose to make. Now the assertion can be exact: a known key adds no fetch, an
unknown one adds precisely one.

The honest limit: a fake proves how your code handles a response, not that your provider
sends that response. Keep one test somewhere that fetches the real JWKS, guard it with a
build tag, and run it on a schedule rather than on every commit.

## Golden tests

`golden_test.go` records the exact bytes this package emits and compares them on every run:
the encoded header for each algorithm, whole tokens for the algorithms whose signatures are
deterministic, JWK and JWKS documents, PEM round trips, `Merge` output, and the JSON shape
of a `TokenPair`. ECDSA and RSA-PSS randomise the signature, so only the signed input is
recorded, taken as `token[:bytes.LastIndexByte(token, '.')]`. Everything up to the last dot
is deterministic and everything after it is not. Copy that split whenever you golden
something with a random component. The file regenerates from a flag, `go test -run
TestGolden -update`.

**A golden whose expectation you edited to match new output proves nothing.** It records
what the code did the last time somebody ran it, and if the only reason the recording
changed is that you ran it again, the test has stopped being a test. That failure mode is
why people distrust golden files, and it is entirely avoidable.

Regenerating is fine. The rule is that you write down the before and the after. This
repository keeps that record in `PASS-LEDGER.md`, one row per change with the old and new
values side by side, so when a reviewer asks why `token/HS256` differs the answer is a line
in a file rather than a memory.

Golden tests also record behaviour you know is wrong: `collectGolden` deliberately captures
the error `GenerateJWK` returns for an ECDSA key, so fixing it shows up as a diff rather
than as silence. A golden file describes current behaviour, not correct behaviour.

## Table-driven tests for the error paths

The error paths are where the interesting behaviour lives, and a dozen of them share one
shape. A table keeps that readable:

```go
for _, tt := range []struct {
	name  string
	token []byte
	want  error
}{
	{"empty", nil, jwt.ErrMissing},
	{"two segments", []byte("header.payload"), jwt.ErrTokenForm},
	{"oversized", bytes.Repeat([]byte("a"), jwt.MaxTokenSize+1), jwt.ErrTokenSize},
} {
	t.Run(tt.name, func(t *testing.T) {
		if _, err := jwt.Verify(jwt.HS256, secret, tt.token); !errors.Is(err, tt.want) {
			t.Fatalf("expected %v but got: %v", tt.want, err)
		}
	})
}
```

Assert with `errors.Is`, never with `err.Error() == "jwt: invalid token form"`. The sentinel
values are part of the package's API and will not change without a version bump. The
strings around them are not, and several are wrapped with context the package is free to
reword. A string comparison passes today and fails on an upgrade that changed nothing you
care about. Where the error carries data, `errors.As` gets you the value: that is how the
package checks its own `*HTTPError`, whose remote body is deliberately kept off the message
and put on a field, because the body is chosen by the host you fetch from and ends up in
whatever you log.

The limit of `errors.Is` is that it names the sentinel, not the call site. `ErrTokenAlg`
comes back from four places in `token.go` alone. When the distinction matters, assert on
something else as well: a status code, the fetch count your fake recorded, or the bytes
that came out.

## Testing that something is refused

A test that a forgery is rejected cannot build the forgery with `Sign`. `Sign` validates the
algorithm name, refuses certain shapes outright, and always attaches a real signature.
Going through it means testing the happy path with a different spelling.

Build the token by hand. `enrich_security_test.go` has a helper for exactly this:

```go
func craftToken(header, payload, signature string) []byte {
	var b bytes.Buffer
	b.Write(jwt.Base64Encode([]byte(header)))
	b.WriteByte('.')
	b.Write(jwt.Base64Encode([]byte(payload)))
	b.WriteByte('.')
	b.WriteString(signature)
	return b.Bytes()
}
```

The header and payload are strings you write out in full, so the test says precisely what
the attacker sent:

```go
// The attacker presents a token claiming the unsecured algorithm and no signature.
forged := craftToken(`{"alg":"NONE","typ":"JWT"}`, `{"sub":"attacker"}`, "")

_, err := jwt.Enrich(jwt.HS256, secret, forged, jwt.Map{"role": "admin"})
if !errors.Is(err, jwt.ErrTokenAlg) {
	t.Fatalf("expected ErrTokenAlg but got: %v", err)
}
```

The same helper builds a token naming a key identifier that will never exist, which is how
`keyset_test.go` checks that twenty such tokens trigger one refetch rather than twenty. Its
signature segment is the literal string `sig`, because the token is refused before anything
decodes it, and writing garbage there documents that fact. Three shapes belong in any suite
that accepts outside tokens: an unsigned token claiming `NONE`, a token signed correctly
with the wrong key, and a token whose payload was edited after signing.

## Replacing Marshal and Unmarshal

Serialization goes through two more package variables. `Marshal` is a function value that
passes a `[]byte` straight through and calls `encoding/json/v2`'s `Marshal` on anything
else, with an option set chosen to match what `json.Marshal` produces; `Unmarshal` is
`defaultUnmarshal`, an `encoding/json/v2` decode with a custom unmarshal hook that
reproduces what `json.Decoder`'s `UseNumber` gave the package before Go 1.27. Replacing
either follows the same save-and-restore discipline as `Clock` and carries the same
parallelism warning.
The usual reasons are counting how many times claims were decoded, injecting a decode
failure that is otherwise hard to provoke, or checking that `jwt.UnmarshalWithRequired`
really does reject a payload missing a required field.

**A middleware that captured the variable at construction will not see your change.** This
is the trap, and it is easy to write by accident:

```go
type Middleware struct{ unmarshal func([]byte, any) error }

func New() *Middleware {
	return &Middleware{unmarshal: jwt.Unmarshal} // read once, right now
}
```

`New` copies the function value out of the variable at the moment it runs. A later
assignment changes the variable and leaves every already-built `Middleware` holding the old
function. If your test constructs the middleware in a `TestMain` or a package-level `var`,
the assignment happens after the capture and the test quietly measures nothing.

Two fixes exist and the second is better. Call `jwt.Unmarshal` at the point of use rather
than storing it. Or stop reading the package variable at all: make the function an explicit
field the caller sets, defaulting to `jwt.Unmarshal` when it is nil. That turns a global
into a parameter, so two tests can want two different unmarshalers at once. The same
reasoning applies in production: `jwt.Unmarshal = jwt.UnmarshalWithRequired` in an `init`
works, and the same line in a request handler, after the middleware was built, may not.

## The race detector

This package's continuous integration runs the suite twice, once plainly and once with the
`safe` build tag, and both runs pass `--race`. It matters more here than in most libraries,
because several types are designed to be used from many goroutines while something changes
underneath them: `KeySet` replaces its key map on refresh, `Blocklist` sweeps expired
entries while revocations arrive, and the package variables are read on every verification.

`TestKeySetIsSafeUnderConcurrentUse` runs eight goroutines doing two hundred verifications
each while a ninth calls `Refresh` fifty times. Without `-race` that test passes whether or
not `KeySet` is actually safe, because a data race usually produces correct answers on the
run where you are watching.

**The race detector does not run everywhere.** On the machine this chapter was written on:

```text
$ go test -race ./...
-race is not supported on windows/arm64
$ echo $?
2
```

The supported platform list is short and windows/arm64 is not on it. The exit code is 2, so
a script that checks it does notice, which is worth confirming rather than assuming: a
refusal that exited zero would let a local run report success without having checked
anything. Run the race build in CI on a platform that supports it; a `linux/amd64` container
substitutes fine.

Two costs. A race build runs several times slower and uses substantially more memory, which
is why it belongs in CI rather than in your edit-compile loop. And the detector reports only
races it observed: one in a path your test never exercised is invisible to it. It finds
bugs, and it does not prove their absence.

## Summary

The suite is hermetic because three seams exist: `Clock` for time, the `HTTPClient`
interface for the JWKS fetch, and `ReadFile` for key files. Two are package variables read
without a lock, so a test that swaps one must not run in parallel with anything else in its
package, and must put the old value back through `t.Cleanup`. Load RSA keys from
`_testfiles/` rather than generating them: a 2048-bit key took 73 to 115 milliseconds to
generate on the machine measured, against about 20 microseconds for an Ed25519 pair.
`MustGenerateRandom(32)` covers HMAC, and `GenerateEdDSA` returns the public PEM first.

Fake the network with a one-method type: a recording fake proves a URL was never requested,
a rotating fake proves a key set was refetched. Golden files pin generated bytes and are
worth nothing unless the regeneration is recorded where a reviewer can read it. Build
forgeries by hand with `craftToken` rather than through `Sign`, assert with `errors.Is`,
and run the result under `-race` on a platform that supports it.

## Further Reading

- [The testing package](https://pkg.go.dev/testing): `t.Cleanup`, `t.Helper`, `t.TempDir`
  and the rules that govern `t.Parallel`.
- [Data Race Detector](https://go.dev/doc/articles/race_detector): how it works, what it
  costs, and the exact list of supported platforms.
- [Table Driven Tests](https://go.dev/wiki/TableDrivenTests): the Go wiki page, including
  the argument for subtests over a bare loop.
- [The errors package](https://pkg.go.dev/errors): `Is`, `As`, and why `%w` makes them work.

---

**Next Chapter**: [Performance](14-performance.md) - What the benchmarks measure, the design decisions behind the numbers, and the parts not worth optimising.
