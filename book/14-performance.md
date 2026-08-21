# Chapter 14: Performance

A JWT library sits on the request path, so its cost is paid once per request forever. This
package is fast for a small number of specific reasons, each of which cost something else:
a precomputed header table that a custom algorithm name walks past, a zero-copy string
conversion with a real aliasing hazard, and a merge that splices JSON text instead of
parsing it. This chapter measures the result on one named machine, explains each decision
with the price attached, and finishes with the parts that are not worth touching.

## Table of Contents

- [The numbers on one machine](#the-numbers-on-one-machine)
- [Where the time goes in a verification](#where-the-time-goes-in-a-verification)
- [Precomputed headers](#precomputed-headers)
- [Bytes to string without a copy](#bytes-to-string-without-a-copy)
- [Merge splices raw JSON](#merge-splices-raw-json)
- [Marshal passes bytes through](#marshal-passes-bytes-through)
- [Base64Decode trims instead of padding](#base64decode-trims-instead-of-padding)
- [Measuring your own usage](#measuring-your-own-usage)
- [What not to optimise](#what-not-to-optimise)
- [The comparison benchmarks](#the-comparison-benchmarks)
- [Summary](#summary)
- [Further Reading](#further-reading)

## The numbers on one machine

Every figure in this chapter was measured on a Snapdragon X X1E80100, twelve cores,
Windows 11, Go 1.27.0, `goos: windows` and `goarch: arm64`. Yours will differ. The ratios
travel better than the absolute times.

The package's own benchmarks, from `go test -bench=. -benchmem -run=XXX` in the repository
root:

```text
BenchmarkSignWithMerge-12            950584     1379 ns/op    1657 B/op    22 allocs/op
BenchmarkSignWithoutMerge-12         558975     2274 ns/op    1586 B/op    30 allocs/op
BenchmarkMerge-12                   1742534      746.0 ns/op   568 B/op    10 allocs/op
BenchmarkStructToMapJSON-12          634286     1894 ns/op     762 B/op    28 allocs/op
BenchmarkStructToMapReflection-12   1000000     1285 ns/op     624 B/op    20 allocs/op
BenchmarkEnrich-12                   403982     3277 ns/op    2777 B/op    39 allocs/op
BenchmarkEncodeToken-12             1000000     1107 ns/op     888 B/op    16 allocs/op
```

The comparison suite, from the same command in `_benchmarks`:

```text
BenchmarkSign_Map-12               694017     1868 ns/op    1441 B/op    27 allocs/op
BenchmarkSign_Struct-12            754218     1566 ns/op    1520 B/op    23 allocs/op
BenchmarkSign_jwt_go_Map-12        392374     2955 ns/op    2250 B/op    43 allocs/op
BenchmarkSign_jwt_go_Struct-12     614936     2512 ns/op    1986 B/op    30 allocs/op
BenchmarkSign_jwt_go_Struct2-12    667363     2185 ns/op    1826 B/op    30 allocs/op
BenchmarkSign_go_jose_Map-12       345763     5158 ns/op    4584 B/op    72 allocs/op
BenchmarkSign_go_jose_Struct-12    181594     6587 ns/op    5944 B/op    93 allocs/op
BenchmarkVerify-12                1000000     1193 ns/op     968 B/op    12 allocs/op
BenchmarkVerify_jwt_go-12          405441     3515 ns/op    2492 B/op    42 allocs/op
BenchmarkVerify_go_jose-12         163896     6320 ns/op    5896 B/op    83 allocs/op
```

Running that second command again, on the same machine and the same binary, moved
`BenchmarkSign_Map` from 1883 to 2092 ns/op and `BenchmarkVerify` from 1211 to 1167. The
byte and allocation columns did not move by a single unit. **Trust the allocation counts and
treat the nanosecond figures as a range.** A change that removes an allocation is a real
change; a change that shaves five percent off one run is probably the scheduler.

The numbers printed in `_benchmarks/README.md` are stale. They were measured years ago on an
Intel i7-8750H under Windows 10, which is a different architecture at a different clock. Do
not compare them with anything above.

## Where the time goes in a verification

`Verify` on an HS256 token does four things: split on the dots and base64-decode the header,
compare the header against a known constant, compute a MAC over the signing input and
compare it against the decoded signature, then base64-decode the payload and unmarshal it.

Measuring the pieces separately, with benchmarks written for this chapter against the same
token the comparison suite uses:

| Piece | Time | Allocations |
| --- | --- | --- |
| `Base64Decode` of one payload segment | 27 ns | 1 |
| `Decode` of a whole token, all three segments | 159 ns | 4 |
| HMAC-SHA256 over the signing input, fresh MAC per call | 425 ns | 7 |
| `Unmarshal` of a 56-byte payload into `Claims` | 427 ns | 3 |
| The whole of `Verify` | 1200 ns | 12 |

Those parts add up to more than the whole, which is the honest result and worth saying
plainly: a microbenchmark of a 66-nanosecond function is measuring its own loop as much as
the function, and the standalone MAC benchmark rebuilds state the real path reuses. Read the
table for ordering, not for a decomposition.

The ordering is the useful part. Base64 is noise. The MAC and the JSON decode are the bill,
and they are roughly the same size. The JSON decode grows with the number of claims, while
the MAC grows only with the raw byte count and does so in 64-byte steps, so the one
optimisation that always works is to put fewer claims in the token. Every claim you move out
of the payload and into a lookup on your side comes off the decode time and the bytes on the
wire together.

## Precomputed headers

For every built-in algorithm the package builds three byte slices once, in `init`, and keeps
them in a map:

```go
type fixedHeader struct {
	raw      []byte // {"alg":"HS256","typ":"JWT"}
	encoded  []byte // the base64url form of raw
	reversed []byte // {"typ":"JWT","alg":"HS256"}
}

var fixedHeaders = make(map[string]*fixedHeader, len(allAlgs))
```

Signing looks the header up rather than building it:

```go
func createHeader(alg string) []byte {
	if header := fixedHeaders[alg]; header != nil {
		return header.encoded
	}

	return Base64Encode([]byte(`{"alg":"` + alg + `","typ":"JWT"}`))
}
```

Verification never parses the header as JSON at all. `compareHeader` decodes the segment and
runs `bytes.Equal` against the precomputed `raw` form, with one branch for producers that
emit the fields in the other order:

```go
if headerDecoded[2] == 't' {
	expectedHeader := createHeaderReversed(alg)
	// ...
}
```

That is a byte comparison against a constant instead of a JSON parse, on every request.

The cost lands in three places. A custom `Alg` whose `Name` is not in the map takes the slow
path: `createHeader` concatenates and base64-encodes on every signature, and
`createHeaderRaw` allocates a fresh slice on every verification. More importantly, a header
this package did not produce is compared byte for byte, so a token carrying an extra header
field, or the same two fields in a third order, fails with `ErrTokenAlg` rather than being
understood. There is also a length gate: `compareHeader` rejects a decoded header shorter
than 25 bytes unless it is exactly 15, the length of `{"alg":"HS256"}`. Interoperating with
a producer outside those shapes means supplying your own `HeaderValidator` through
`VerifyWithHeaderValidator`, which parses properly and costs what parsing costs.

## Bytes to string without a copy

Converting a `[]byte` to a `string` in Go allocates and copies. The package does not:

```go
func BytesToString(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}
```

The returned string points at the caller's bytes. There is a second implementation behind
the `safe` build tag that is a plain `string(b)` conversion, and the continuous integration
runs the full suite under both.

The hazard is aliasing, and it is not theoretical. A string in Go is immutable by contract,
not by enforcement. `BytesToString` hands you one whose backing array somebody else still
owns, and if they write to it your string changes underneath you. The place this bites is
`Blocklist`. When a token carries no `jti`, the blocklist key is the whole token, produced
by `BytesToString`, and a map key whose contents change is a map key that can no longer be
found. So `InvalidateToken` copies before storing:

```go
key = strings.Clone(key)
```

One allocation, on a path that runs once per logout rather than once per request. Lookups
keep the zero-copy form, because a lookup does not retain the string.
`TestInvalidateTokenDoesNotAliasTheCallerBuffer` hands the blocklist a buffer, overwrites
every byte of it, and checks the revocation still matches.

**Measure before you assume the tag is expensive.** Running the comparison suite with
`-tags safe` gave `BenchmarkVerify` at 1020 ns/op, 968 B/op, 12 allocs/op, which is inside
the run-to-run variation of the default build for this workload. If you cannot audit every
caller that hands this package a reused buffer, build with `-tags safe` and spend the
difference elsewhere.

## Merge splices raw JSON

`func Merge(values ...any) ([]byte, error)` combines claim sets. The obvious implementation
unmarshals everything into a `map[string]any`, merges the maps, and marshals the result.
This one strips the outer braces off each part and joins the insides with commas:

```go
inner := jsonBytes[1 : len(jsonBytes)-1]
parts = append(parts, inner)
// ...
combined = bytes.Join([][]byte{[]byte("{"), bytes.Join(parts, []byte(",")), []byte("}")}, nil)
```

Never unmarshalled, never re-marshalled. The repository benchmarks the three approaches
side by side, which is how the decision was made in the first place: `BenchmarkMerge` at
746 ns and 10 allocations, against 1894 ns and 28 allocations through a map, and 1285 ns and
20 allocations through reflection. End to end, `BenchmarkSignWithMerge` runs at 1379 ns and
22 allocations where `BenchmarkSignWithoutMerge` needs 2274 ns and 30.

The cost is duplicate keys. Merging `{"role":"admin"}` with `{"role":"user"}` produces
`{"role":"admin","role":"user"}`. That is well-formed JSON, and RFC 8259 declines to say
which value wins: Go's `encoding/json` takes the last, and other parsers take the first. The
golden file records the result under `merge/duplicate-key` so nobody has to guess what the
package does. The rule for callers is short. Never merge two objects that can carry the same
claim, and if you cannot guarantee that, put the object whose values should win last.

One check does survive. A `string` or `[]byte` part is spliced in verbatim, so `Merge` runs
`json.Valid` over exactly those two cases. Without it, `{"broken"}` passed the first-and-last
byte test and produced a signed token whose payload was not JSON.

## Marshal passes bytes through

The default `Marshal` starts with a type switch:

```go
var Marshal = func(v any) ([]byte, error) {
	if b, ok := v.([]byte); ok {
		return b, nil
	}

	return jsonv2.Marshal(v, marshalOptions)
}
```

Since Go 1.27 the non-`[]byte` case runs on `encoding/json/v2` rather than `encoding/json`,
with an option set chosen to match `json.Marshal`'s output byte for byte: sorted map keys,
the same character escaping, the same leniency toward invalid UTF-8. The move to v2 buys
speed without changing what gets signed.

`Merge` returns `[]byte`, `Sign` hands its claims to `Marshal`, and the payload therefore
reaches the encoder without a second serialization. It also means you can cache a payload:
marshal your claims once, keep the bytes, and sign them repeatedly for the price of the
signature alone.

The cost is that a `[]byte` is taken at its word. `Marshal` does not check it is JSON, so
`Sign(alg, key, []byte("not json"))` produces a signed token whose payload is not JSON, and
the failure surfaces at whoever verifies it. `Merge` covers its own raw inputs with
`json.Valid`; the direct path to `Sign` is yours to get right.

## Base64Decode trims instead of padding

A JWT segment carries no base64 padding, and `base64.URLEncoding` wants input whose length
divides by four. The obvious fix is to append `=` characters until it does, and this package
did that for years. What replaced it goes the other way:

```go
func Base64Decode(src []byte) ([]byte, error) {
	src = bytes.TrimRight(src, padStr)

	buf := make([]byte, base64.RawURLEncoding.DecodedLen(len(src)))
	n, err := base64.RawURLEncoding.Decode(buf, src)
	return buf[:n], err
}
```

Trimming rather than appending was a correctness fix first. The functions that split a
token into its three parts (`bytes.Split` for a long time, `bytes.CutLast`/`bytes.Cut`
since Go 1.27) do not cap the capacity of the last part they return, so the signature
segment of a token still owns the token's spare capacity, and appending to it wrote past
the end of the caller's buffer. With a pooled HTTP read buffer, which is how most servers
hand a token to this package, that is a write into memory the next request is about to
use.

It was also faster, and by more than anyone expected. `bytes.TrimRight` returns a sub-slice
and allocates nothing, `RawURLEncoding` needs no padding, and `DecodedLen` on the trimmed
input asks for a smaller buffer than the padded form did. The recorded before and after for
`BenchmarkVerify`: 22 allocations, 1632 B and 2821 ns became 18 allocations, 1376 B and
2455 ns. Four allocations and 256 bytes off every single verification, for a change that was
made to stop a memory corruption.

## Measuring your own usage

The command is the one used throughout this chapter:

```sh
go test -bench=. -benchmem -run=XXX
```

`-benchmem` adds the two columns that matter. `-run=XXX` gives the test filter a pattern
nothing matches, so the tests do not run and their time stays out of the result. Call
`b.ReportAllocs()` and put `b.ResetTimer()` after any setup, or the key you generated in the
benchmark body ends up in the measurement.

The counts to expect, on the small token these benchmarks use: 12 allocations to verify with
HS256, 23 to sign a struct, 27 to sign a map. If yours are much higher, look at your claims
type before you look at the package. A map costs more than a struct because `encoding/json`
sorts the keys and boxes every value. A struct with twenty fields costs more than one with
four. A `time.Time` field costs more than an `int64`.

For comparing two versions of your own code, run each with `-count=10` and put the output
through `benchstat`. A single pair of runs cannot tell a five percent change from noise, and
this chapter's own second run is the proof: the same binary, the same machine, 1883 ns and
then 2092 ns for the same benchmark.

## What not to optimise

The signature is the floor, and with anything other than HMAC it is most of the building.
Verification of the same small token, by algorithm:

| Algorithm | Verify | Allocations |
| --- | --- | --- |
| HS256 | 915 ns | 11 |
| RS256 | 27178 ns | 16 |
| EdDSA | 34546 ns | 5 |
| ES256 | 43500 ns | 27 |

Signing with RS256 measured 1165527 ns, a little over 1.1 milliseconds. That is the RSA
asymmetry doing its usual thing: verification uses a public exponent of 65537 and is cheap,
signing uses the private exponent and is not, and the gap here is a factor of forty-three.

Read the RS256 row against the HS256 row. The package's own work is identical in both and
runs on the order of a microsecond; the extra 26 microseconds is the RSA verification
itself, modular arithmetic in `crypto/rsa`. Shaving another allocation off the parsing path
would move an RSA verification by well under one percent, and an RSA signing by roughly
nothing.

So do not tune the library for an RSA workload. Tune the number of RSA operations. Verify
once per request rather than once per handler. Give access tokens a short life and a cheap
algorithm and keep RSA for the refresh path. If you control both ends, EdDSA verification
costs about the same as RS256 here while using five allocations instead of sixteen, and
EdDSA signing measured 14989 ns against RS256's 1165527, a factor of seventy-eight.

The other thing not worth optimising is the constant-time comparison in the HMAC path. It is
there so that a wrong signature takes the same time to reject as a nearly-right one, and
replacing it with `bytes.Equal` would buy nanoseconds and sell an oracle.

## The comparison benchmarks

`_benchmarks` compares this package against `github.com/golang-jwt/jwt` v3.2.2 and
`github.com/go-jose/go-jose/v3` v3.0.4. Verification, from the run quoted above:

| Package | Verify | Bytes | Allocations |
| --- | --- | --- | --- |
| `kataras/jwt` | 1193 ns | 968 | 12 |
| `golang-jwt/jwt` | 3515 ns | 2492 | 42 |
| `go-jose/go-jose` | 6320 ns | 5896 | 83 |

The second run gave 1211, 3464 and 6919 for the same three. The timing ratio is not a fixed
multiple and this book will not quote one. The allocation ratio held exactly across both
runs, and that is the number worth carrying: a little over a quarter of `golang-jwt`'s
allocations and under a sixth of `go-jose`'s.

Two caveats belong next to those figures. `go-jose`'s `ParseSigned` does not verify anything;
the benchmark has to call `Claims` afterwards to force the signature check, so the two sides
are not calling equivalent APIs. And `golang-jwt/jwt` v3.2.2 is an old major version, kept
because that is what the benchmark module pins. A current v5 would be a fairer comparison and
has not been measured here.

## Summary

Signing a struct with HS256 took about 1.6 microseconds and 23 allocations on the machine
named above; verifying took about 1.2 microseconds and 12 allocations. Timings moved by
roughly ten percent between two runs of the same binary while allocation counts did not
move at all, so allocations are the metric to hold a change to.

Inside a verification, base64 decoding is noise and the MAC and the JSON unmarshal are
roughly equal halves of the cost. Four decisions buy the rest: a precomputed header table,
which a custom algorithm name and an unusual field order walk past; a zero-copy
`BytesToString`, which aliases the caller's buffer and forces a `strings.Clone` in the
blocklist; a `Merge` that splices raw JSON and therefore emits duplicate keys rather than
resolving them; and a `Base64Decode` that trims padding, which removed four allocations from
every verification and fixed a write past the end of the caller's buffer at the same time.

Above HMAC, the signature dominates everything else. RS256 verification measured 27
microseconds against HS256's 0.9, and RS256 signing 1.2 milliseconds. Optimise the number of
those operations rather than the code around them.

## Further Reading

- [Benchmarks in the testing package](https://pkg.go.dev/testing#hdr-Benchmarks): what
  `b.N`, `b.ResetTimer` and `b.ReportAllocs` actually do.
- [benchstat](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat): the tool for deciding
  whether two sets of benchmark runs differ.
- [Profiling Go Programs](https://go.dev/blog/pprof): `-cpuprofile` and `-memprofile`, and
  how to read what comes out.
- [unsafe.String](https://pkg.go.dev/unsafe#String): the exact contract, including the rule
  that the bytes must not be modified while the string is alive.
- [RFC 8259 section 4](https://www.rfc-editor.org/rfc/rfc8259#section-4): the paragraph that
  leaves duplicate object names up to the implementation.

---

**Next Chapter**: [Epilogue](epilogue.md) - The shape every defect in this book turned out to share, and what the package will not do for you.
