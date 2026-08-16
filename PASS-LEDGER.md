# Pass ledger

A running record of what was decided, why, and what it costs if the decision turns out wrong.
This file and `COMMIT-PLAN.md` are working documents for one pass. Delete them once the work is
committed, or keep them; they are yours.

## Standing constraints

| Constraint | Source |
| --- | --- |
| Performance and memory come first. Code that reads badly but exists for speed stays. | Author, during planning |
| Breaking changes are allowed. The pass cuts v0.2.0. | Author, during planning |
| The assistant stages with `git add` and never commits. | Author, during planning |
| Consumers studied: `pnoe-core-go`, `pnoe-nut-go`, `iris-private`. | Author, during planning |

## Benchmark baseline

Recorded before any source change, Go 1.26.5, windows/arm64, `go test -bench=. -benchmem`.
Every later measurement in this file is compared against these.

**In-package** (`github.com/kataras/jwt`)

| Benchmark | ns/op | B/op | allocs/op |
| --- | --- | --- | --- |
| SignWithMerge | 2583 | 1520 | 20 |
| SignWithoutMerge | 3094 | 1705 | 25 |
| Merge | 583.3 | 432 | 8 |
| StructToMapJSON | 1933 | 1040 | 28 |
| StructToMapReflection | 1143 | 744 | 15 |
| Enrich | 4368 | 2961 | 39 |
| EncodeToken | 1890 | 912 | 15 |

**Against other libraries** (`_benchmarks`)

| Benchmark | ns/op | B/op | allocs/op |
| --- | --- | --- | --- |
| Sign_Map | 2487 | 1528 | 23 |
| Sign_Struct | 2362 | 1392 | 21 |
| Sign_jwt_go_Map | 3809 | 2377 | 37 |
| Sign_jwt_go_Struct | 3065 | 1913 | 27 |
| Sign_go_jose_Map | 5646 | 4584 | 72 |
| Sign_go_jose_Struct | 8438 | 5944 | 93 |
| Verify | 2821 | 1632 | 22 |
| Verify_jwt_go | 4582 | 3088 | 51 |
| Verify_go_jose | 7749 | 5896 | 83 |

The margin over `golang-jwt` on verification is 1.6x on time and 2.3x on allocations. That
margin is the reason the library exists, so it is the number to defend.

## Review gate: the Enrich fix

An independent adversarial review confirmed all five intended security properties, and
found six defects worth acting on. Each was reproduced before it was fixed.

| Finding | Verdict | Action |
| --- | --- | --- |
| A typed-nil public key panics. `*rsa.PublicKey(nil)` in an interface is not nil, so it passed every nil check, asserted successfully and crashed inside `crypto/rsa`. Any token naming that `kid` took the process down. | Reproduced. I ran it: `invalid memory address or nil pointer dereference` in `crypto/rsa.checkPublicKeySize`. | Nil guards on every key assertion in `rsa.go`, `rsapss.go`, `ecdsa.go`, and a length guard in `eddsa.go` before `Public()`, which slices at `[32:]`. |
| The package's own documented HMAC registration does not work. `Register(HS256, "k", nil, secret)` stored a nil public key and every verification failed with `ErrInvalidKey`. | Confirmed. | `Register` fills a nil public key from the private one for HMAC, where they are the same key. |
| `publicKeyOf` accepted a `string`, which produced a working verification key and then failed at signing. | Confirmed. | Dropped. No algorithm here signs with a string, so accepting it only moved a clear rejection to a confusing place. |
| `Keys.EnrichToken` failed for any custom `Alg`, because it read the `kid` through `UnverifiedToken.Kid`, which also resolves the algorithm against the built-in list. | Confirmed. | Reads `kid` from the verified header directly. The lookup was redundant anyway, since `ValidateHeader` had already resolved the key. |
| `Merge` splices raw JSON, so a claim restated in `extraClaims` appears twice and Go reads the last one while other languages read the first. | Confirmed, and already on the list as audit item 20. | Documented on `Enrich` now, fixed in the `Merge` task group. |
| One test assertion did not test what its name claimed: the "foreign signature" token had no `kid`, so it was turned away by `ErrEmptyKid` before the signature was ever checked, and would have passed against the old code. | Confirmed. This is the reviewer's most useful finding. | Rewritten to use a token carrying the right `kid` signed with a different secret, asserting `ErrTokenSignature`. A separate assertion covers the no-`kid` case. |

The reviewer also judged `TestEnrichKeepsAVerifiedHeader` not load-bearing for security,
which is correct: the old code carried the header through too. Its comment now says so.

## Measurements after each change

| Change | Benchmark | Before | After |
| --- | --- | --- | --- |
| Group 2, nil-alg guard in `decodeToken` | Verify | 22 allocs, 2821 ns | 22 allocs, 2739 to 2880 ns |
| Group 2, nil-alg guard in `decodeToken` | Sign_Map / Sign_Struct | 23 / 21 allocs | 23 / 21 allocs |
| Group 3, `Enrich` now verifies | Enrich | 39 allocs, 2961 B, 4368 ns | 47 allocs, 3562 B, 5411 ns |
| Group 8, `Base64Decode` trims padding instead of appending it | **Verify** | 22 allocs, 1632 B, 2821 ns | **18 allocs, 1376 B, 2455 ns** |
| Group 8, `json.Valid` on raw Merge fragments | Merge | 8 allocs, 432 B, 583 ns | 8 allocs, 432 B, 518 ns |
| Group 8, same | SignWithMerge | 20 allocs, 1520 B, 2583 ns | 20 allocs, 1520 B, 2343 ns |

The `Base64Decode` change is the one worth reading twice. Appending `=` bytes to reach a
multiple of four wrote into the caller's buffer, because `bytes.Split` does not cap the
last part it returns. Trimming instead and decoding with `base64.RawURLEncoding` fixes that
and removes an append, a possible reallocation and a larger `DecodedLen` request: four
allocations and 256 bytes off every single verification, and about 12 percent of the time.
The safest version was also the fastest one.

`json.Valid` costs nothing measurable because only the `string` and `[]byte` fragments are
checked. Anything that went through `json.Marshal` is valid by construction and skips it.

The Enrich figure is the honest price of checking a signature that was not checked at all
before. It landed at 58 allocations first, using `Verify`; dropping to `decodeToken` took
off 7 and using `json.Unmarshal` for the one-field header parse took off 4 more.

## Deliberate output changes, before and after

Every one of these was caught by the golden tests rather than asserted into place. The
golden file was regenerated only after the change was read here.

| Entry | Before | After |
| --- | --- | --- |
| Unsecured algorithm name | `{"alg":"NONE","typ":"JWT"}` | `{"alg":"none","typ":"JWT"}`, which is what RFC 7518 section 3.6 says. Tokens this package produced under the old name were not valid unsecured JWTs anywhere else, and conforming ones were never accepted here. |
| RSA JWK | `{"kty":"RSA",…,"crv":"","n":"…","e":"AQAB","y":"","x":""}` | `{"kty":"RSA",…,"n":"…","e":"AQAB"}`. Members that do not apply to a key type are now absent, as RFC 7517 requires. Some consumers reject the empty ones. |
| Ed25519 JWK | `{…,"crv":"Ed25519","n":"","e":"","y":"","x":"…"}` | `{…,"crv":"Ed25519","x":"…"}` |
| ECDSA JWK from a `*ecdsa.PublicKey` | the error `unsupported public key type: *ecdsa.PublicKey` | a correct EC JWK. Every ECDSA key this package produces is a pointer, so `Keys.JWKS()` failed for every ES256, ES384 and ES512 key. |
| `Keys.JWKS()` with an ECDSA key | the same error | a key set. |
| `NewTokenPair(nil, nil)` marshalled | `{"access_token":"","refresh_token":""}` | `{}`. The fields were `json.RawMessage` filled by a helper that wrapped bytes in quotes, so an empty token became the two-byte value `""` and `omitempty` never fired. |

`Keys.JWKS()` also returned its keys in map order, which changes between calls, so a
served `/.well-known/jwks.json` had a different body every time and defeated ETag and
If-None-Match on a document that only changes when a key is rotated. It now sorts by key
id. This one was found by accident: the golden test failed at random until I looked at
why, and the first version of the test papered over it by sorting in the test instead.

## Environment findings

| Finding | Consequence |
| --- | --- |
| `-race` does not run on windows/arm64. | Local runs are `go test ./...`. CI keeps `--race` on ubuntu, so races are caught there and not here. |
| The local clone is missing tags `v0.1.16` and `v0.1.17`. | The latest published version is `v0.1.17`, which is what all three consumers pin. `git tag` in this clone under-reports. Version the changelog against v0.1.17, not v0.1.15. |
| `_examples` has no `go.mod`. | `_examples/multiple-kids` cannot build, because it imports `gopkg.in/yaml.v3` and resolves against the library's zero-dependency module. |

## Decisions

| # | Decision | Why | Cost if wrong |
| --- | --- | --- | --- |
| 1 | Treat every subagent finding as a claim and read the source before acting. | The security survey reported a `Leeway` plus `Blocklist` revocation bypass. `verify.go:491` breaks the validator loop on the first error, so a validator only ever sees a non-nil incoming error when it is first in the list, and the blocklist never sees Leeway's. The finding was wrong. | Verification costs time on findings that were right anyway. Acting on a confident wrong finding costs more. |
| 2 | `ErrExpired` comparison at `blocklist.go:129` downgraded from bug to hygiene. | Grep confirms `ErrExpired` is never wrapped anywhere in the package, and decision 1 shows the blocklist cannot receive a wrapped one. `errors.Is` is still the right idiom for callers who wrap it themselves. | If a future change wraps `ErrExpired`, the `==` silently stops matching. `errors.Is` costs nothing, so it goes in anyway. |
| 3 | `GenerateEdDSA`: the body is correct, the return types are the defect. | `_examples/generate-ed25519/main.go:17` writes the return values straight to `.pem` files, so PEM output is the intent. The `ed25519.PublicKey` and `ed25519.PrivateKey` return types are wrong and only compile because both are `[]byte`. | If PEM was not the intent, the fix renames the wrong half of the API. The example is strong evidence, and the doc comment agrees with it. |
| 4 | `Enrich` takes the algorithm as a parameter and verifies the signature before re-signing. Breaking. | The algorithm came from the unverified header, so a caller could be handed `{"alg":"NONE"}` and emit an unsigned token, or be made to sign an attacker's header with its own private key. No amount of documentation fixes a default that hands out signatures. | Every call site must add an argument. If a caller genuinely enriched tokens it had not verified and relied on that, it now fails closed. The escape hatch is `Decode` plus `UnverifiedToken.Enrich`. |
| 5 | `Enrich` uses `decodeToken`, not `Verify`. | `Verify` also unmarshals the standard claims and runs the validator chain. That is 11 allocations Enrich does not need, and it answers a question Enrich does not ask: the enriched token keeps the original `exp`, so whoever verifies it next still checks expiry. | An expired token can be enriched. The result is still expired and still fails downstream, so this is a cost in clarity rather than in safety. |
| 6 | A verified header is carried through; an unverified one is regenerated. | The first version regenerated in both cases, which silently stripped `kid` and broke `Keys` round trips. A header that survived verification was covered by a signature made with the caller's own key, so it is not attacker chosen and is safe to keep. | If a caller's own signing key is compromised, header fields are the least of the problem. `UnverifiedToken.Enrich` still drops everything, which is the conservative half. |
| 7 | A revocation for a token without `exp` is stored as never expiring rather than refused. | It is the only answer that matches the token: a token with no `exp` is valid forever, so its revocation has to be too. Refusing would break callers who revoke such tokens today. | Those entries are never collected, so memory grows with the number of revoked non-expiring tokens. That is the correct amount of memory, but a caller who mints many such tokens and revokes them will notice. Documented on the method. |
| 8 | `GC` holds one write lock for the whole sweep. | The mark-then-delete form could delete an entry that was re-added in between, silently un-revoking a live session. Correctness beats the shorter critical section here. | Verification blocks for the length of a sweep, proportional to the number of revocations still inside their lifetime. For a blocklist large enough to matter, that is a latency spike on a timer. |
| 9 | `strings.Clone` on the blocklist key at insert, and not at lookup. | Without a `jti` the key is `BytesToString(token)`, which shares the caller's buffer, and a map key's contents must not change underneath it. Lookups do not retain the string, so they keep the zero-copy path. | One allocation per revocation, which happens on logout rather than per request. The hot path is untouched. |
| 10 | `defaultGetKey` is exported as `DefaultBlocklistKey`. | A downstream Redis backend re-derived it, returned the `jti` unconditionally, and mapped every token without one to the empty key. One logout blocked every session in the system. Exporting it removes the reason to guess. | It is now API surface that has to keep working. The behaviour is three lines and unlikely to change. |

## Phase 4: the brand kit

You picked direction 03, Token Key. Decisions taken while building it:

| # | Decision | Why | Cost if wrong |
| --- | --- | --- | --- |
| 11 | The palette is a sibling of the Iris kit, not a copy: gold `#F5C542` carried over unchanged, blue moved from Iris indigo to Aegean `#0D5EAF`. | The gold is what makes the two projects look related; a shared blue would make the two marks hard to tell apart at favicon size. | If the two are meant to be interchangeable rather than related, the blue is wrong and one line in `mark.go` changes it. |
| 12 | The generator is its own Go module at `brand/`, with no dependencies, shelling out to Chrome for rasterization. | The library keeps zero dependencies and a nested module is excluded from the parent, so nothing here can leak into `go.mod`. Chrome does SVG to PNG and the ICO container is 22 lines of `encoding/binary`. | A checkout with no browser cannot rebuild the PNGs. It writes the SVGs, says so, and exits zero, and the PNGs are committed. |
| 13 | The small-size cut boundary is 48 px. | Chosen by rendering both cuts at 16, 24, 32 and 48, magnifying eight times and looking, not by picking a round number. | Too low and the three teeth merge into a wedge; too high and the mark looks unnecessarily crude at 64. |
| 14 | The small cut has a **thinner** ring stroke than the full cut, and a larger radius. | Counterintuitive and load-bearing. What has to survive is the light gap between the hole and the ring: at 16 px it was about one pixel, went sub-pixel under antialiasing and closed into a grey smear that took the whole bow with it. Widening the gap beats thickening the ink. | Someone "fixing" the small cut by thickening every stroke uniformly reintroduces the smear. The reasoning is in the comment above `markSmallBody`. |
| 15 | The README logo is 72 px, and the coverage badge was removed. | GitHub caps the README column at about 1012 px, so the intro paragraph wraps to two lines and the mark overhangs by roughly 30 px, which `<br clear="left"/>` absorbs. Rendered at 900 and 1800 px and looked at. The badge was a hardcoded static image claiming 92 percent, linking to a dead travis-ci.org job, while `jwk.go` and `kid_keys.go` had no tests at all. | If a real coverage badge is wanted, it needs a CI step that measures it. Removing a false one is not the same as adding a true one. |

Three of the six candidate directions looked fine as markup and fell apart the first time
they were rendered: the Meander collapsed into a plain square with no Greek key visible,
the gopher read as a bear, and the shield's cut vanished by 32 px. That is the argument for
rendering before presenting, and it is why `BRAND.md` says to do it again after any change.

## Files that appeared during the pass

`skill/jwt/SKILL.md` and the five documents under `skill/jwt/references/` were not written
by this pass. They appeared while the brand kit was being built.

They are accurate. Verified rather than assumed: all 111 function signatures the API map
claims were compared against `go doc -all`, and 107 matched exactly. The four that did not
differed only in parameter names and named return values, with identical types and
arities, and have been corrected so the document matches the source exactly. Every
`jwt.X` symbol named anywhere in the skill exists in the package.

That check matters more than usual here, because the whole purpose of an API map is to stop
an assistant inventing a signature, and this pass changed several of them.

## Phases 5 to 9

| # | Decision | Why | Cost if wrong |
| --- | --- | --- | --- |
| 16 | The book is its own module at `book/`, with three dependencies. | The library keeps none, and a nested module is excluded from the parent. gomarkdown, chroma and yaml are what a book generator needs; writing them by hand would be a worse use of the pages. | A contributor without those in their module cache needs network access to build the book. The rendered output is committed, so reading it does not. |
| 17 | The chapter skeleton is enforced by the build, in `book/validate.go`. | The generator already parsed the H1, the contents block and the footer literally. A chapter that breaks the skeleton fails quietly: a missing Summary stops mid-thought, and a contents link whose anchor does not resolve simply goes nowhere. | A legitimate chapter shape that the validator does not know about cannot be built without changing the validator. That is the intended trade. |
| 18 | Front and back matter carry no contents block, Summary or Further Reading. | A preface with a Summary is repeating itself in four hundred words. | If a preface ever needs one, the rule is one line in `validate.go`. |
| 19 | No version anywhere in the book or on its cover. | The library's version changes with every release and the book does not. A number on the cover is wrong the week after it is printed, and nobody regenerates a PDF to fix one. | Somebody reading an old PDF cannot tell which release it describes. The chapters name behaviour rather than versions, except chapter 12, which lists what changed in v0.2.0 explicitly. |
| 20 | Chapters were drafted by subagents and verified here. | Fourteen chapters of accurate prose is a lot of writing. Each agent was given the skeleton, the writing standard, and an instruction to check every signature against `go doc -all` rather than memory. | A drafting agent could still invent an API. Checked mechanically: every `jwt.X` named anywhere in the book exists in the package, and the build refuses a chapter whose contents anchors do not resolve. One agent's report also found a real defect in `Classify`, described below. |
| 21 | Local agent configuration stays out of the repository; `skill/` is the tracked, published copy. | Author's call, recorded below. Everything a reader needs is in `skill/`, the book and the changelog, so nothing published depends on a file a clone will not have. | The automation that kept the skill mirror and the book output current does not travel, so both have to be rebuilt by hand. `book/README_EBOOK.md` lists what to watch. |
| 22 | `_examples` gets its own `go.mod`. | `_examples/multiple-kids` imports `gopkg.in/yaml.v3` and had no module of its own, so it resolved against the library's zero-dependency module and simply did not build. Nothing in CI compiled it, so nobody noticed. | The examples now need their own `go mod tidy` when a dependency changes. That is the price of them being buildable at all. |
| 23 | The golden file records PEM output as a SHA-256 rather than verbatim. | It was only the committed test fixtures, so nothing secret was at stake, but a golden file full of `BEGIN PRIVATE KEY` is alarming to anyone scanning the repository and puts a second copy of key material in the tree for no benefit. A digest fails on any encoder change just as well. | If somebody needs to eyeball the exact PEM a change produced, they have to print it rather than read the golden. |
| 24 | `doc.go` was rewritten rather than edited. | It opened with claims that were not true (a comparison to other libraries, "zero-allocation parsing"), documented testing utilities that do not exist, defined an example type shadowing the package's own `TokenValidator`, and used six `##` headings that godoc renders as literal text. Editing around that would have left the shape of a document written to impress. | The new one is shorter and covers less. Everything it drops is in the book or in `go doc` for the symbol itself. |

## A defect found by a drafting agent

The agent writing chapters 2 and 3 reported that `Classify`'s documentation claimed
`KindMalformed` covered a bad base64 segment and a non-JSON payload, while the switch named
neither, so both actually returned `KindInvalid`.

Verified by running it: a token of `!!!.!!!.!!!` produced `illegal base64 data at input
byte 0` and classified as `invalid`, and a non-JSON payload produced
`jwt: payload is not a type of JSON` and did the same.

Fixed in the code rather than the comment, because malformed is the right answer for both:
`Classify` now matches `base64.CorruptInputError` with `errors.As` and the unexported
`errPayloadNotJSON` with `errors.Is`. The chapter, which had documented the observed
behaviour rather than the comment, was corrected to match.

That is the second time in this pass that an independent reader found something the author
of the code did not. The first was the review of the `Enrich` fix.

## Subagent reports that were wrong

The ground rule for this pass was to treat every subagent finding as a claim and check it.
Three were checked and found wrong, which is the argument for the rule.

**The security survey claimed a revocation bypass through `Leeway` and `Blocklist`.** The
reasoning was that `Leeway` returns `ErrExpired` for a token that is still valid, and
`Blocklist.ValidateToken` deletes its entry when it sees that error. Both halves are true.
The conclusion is not: `verify.go` breaks the validator loop on the first error, so a
validator only ever receives a non-nil incoming error when it is first in the list, and the
blocklist never sees Leeway's. Downgraded to hygiene, and `errors.Is` went in anyway.

**A drafting agent claimed `go test -race` exits zero on this platform,** and built a
paragraph of chapter 13 on it: that a script checking the exit code would report success
without having checked anything. Run here, it prints `-race is not supported on
windows/arm64` and exits **2**. The chapter now says so, and shows the exit code rather than
asserting it.

**The same agent's report was right about three other things,** including a real defect in
`Classify`, so the answer is to check rather than to discount.

## Overridden by the author

Decision 21 originally tracked the local agent configuration, on the argument that a clone
without it loses the build automation. The author ruled the other way and gitignored it, so
it was taken out of the index and left on disk.

That leaves nothing published pointing at it. Every reference was removed rather than left
dangling: the changelog entry that listed it as a deliverable, the scope section and corpus
list in `skill/human-writing`, and the automatic-rebuild section of `book/README_EBOOK.md`,
which now says which inputs to watch and to rebuild by hand.

The content itself did not need a home elsewhere. The invariants and the sharp edges are
chapter 12 of the book and the `skill/jwt` reference, both of which are published; the
configuration file only ever restated them for a local assistant.

## Final measurements

Windows/arm64, Go 1.26.5, `go test -bench=. -benchmem`, three runs.

| Benchmark | Baseline | Now |
| --- | --- | --- |
| Verify | 22 allocs, 1632 B | **18 allocs, 1376 B** |
| Sign_Map | 23 allocs, 1528 B | 23 allocs, 1528 B |
| Sign_Struct | 21 allocs, 1392 B | 21 allocs, 1392 B |
| Enrich | 39 allocs, 2961 B | 47 allocs, 3562 B |

Timings moved between runs by up to 30 percent on an otherwise idle-looking machine, while
allocation counts did not move at all. Allocations are the number to hold a change to.

Verification is four allocations and 256 bytes cheaper than it was at the start of this
pass, which was a side effect of fixing a buffer-aliasing bug rather than the point of it.
Enrichment is eight allocations dearer, and that is the price of checking a signature that
was not checked at all before.

## Two more found while writing about the code

Writing prose about code turns out to be a good way to find defects in it, because it
forces somebody to state plainly what a function does and then check.

**`InvalidateToken` accepted a key it could never look up.** A `GetKey` that returns the
`jti` unconditionally, which is the downstream mistake that caused an outage, produces an
empty key for any token without one. `Has` refuses an empty key with `ErrMissing`, so the
entry sat in the map matching nothing: `InvalidateToken` returned `nil`, `Count` went up by
one, and `ValidateToken` let the token straight through. Reproduced, then fixed:
`InvalidateToken` refuses an empty key and the message says what to do about it.

**`Keys.JWKS()` refused a registry containing an HMAC key**, and so did
`Keys.Configuration()`. Both are ordinary things to have. `JWKS` now skips symmetric keys,
which is the correct semantic rather than a workaround: publishing an HMAC secret at
`/.well-known/jwks.json` would hand out the ability to mint tokens. `Configuration` exports
them, because a configuration file is where a shared secret legitimately lives, and the
round trip is tested.

Also from the same source: `SignToken`'s comment claimed the key's `MaxAge` beats a
caller-supplied one. The key's is prepended, so the caller's applies afterwards and wins.
The comment was wrong, and the behaviour is the useful way round.

## The PDF pipeline needed a dependency after all

The first version shelled out to `chrome --print-to-pdf` with `--virtual-time-budget`,
which is the documented way to let a page finish before printing, and which avoided adding
a dependency to the book module.

It does not work here, and the failure is worth recording because it looks like success.
The pagination polyfill lays the book out after load, and `--print-to-pdf` prints at the
load event. Measured on this book: a budget of 60 seconds produced a 1230-byte blank page,
120 seconds produced 53 KB, and 300 and 600 seconds both produced the same 1230-byte blank
page again. It is not a matter of waiting longer.

So the book module gained `chromedp`, which drives the browser over the DevTools protocol:
navigate, watch the page count until it stops moving, then print. 210 pages, 1.9 MB,
repeatably. The size guard that caught the blank output in the first place is still there.

The library still has no dependencies. That is what the nested module is for.

## One more, and a correction to record

**`Plain`'s doc comment recommended the one placement that stops it working.** It said to
put it last, "so it can catch JSON errors that other validators might depend on". Verified
by running it: with `Plain` last, a non-JSON payload returns `jwt: payload is not a type of
JSON`, because the validator ahead of it receives that error, returns it, and the loop
breaks before `Plain` executes. With `Plain` first, it clears the error and the chain
continues. The comment now says the opposite, `errors.Is` replaced an `==`, and a test pins
all three orderings.

That is the fourth defect found by somebody writing prose about the code rather than by a
test, and the second where the documentation recommended the failure it was meant to
prevent. The other was `SignToken`'s `MaxAge` precedence.

**Correction to an earlier note in this file.** I recorded that I had overwritten a
concurrently-written draft of chapter 9. The agent's own account is the opposite: it found
the chapter already present when it went to save, verified it against the source rather than
clobbering it, corrected two statements that credited the signature check with rejecting an
expired token (that is the claim check), and added the empty-key passage. Nothing was lost.
The chapter has two authors.

## The book was clipping its code, and I did not look

You caught this, and it is the plainest failure of the pass: I verified the book's
structure, its skeleton, its anchors, its signatures and its prose, and I looked at the
cover and the contents page. I never looked at a page with a long listing on it.

`pre.code` carried `overflow-x: auto`, which is meaningless on paper. There is no scrollbar,
so everything past the right edge was cut off with no indication that anything was missing.
On a 6 by 9 trim with 16mm margins that is 120mm of measure, about 67 monospace characters,
and `VerifyEncryptedWithHeaderValidator` alone is 34. Measured across the book: 39 of 1347
code lines are 90 characters or longer, and the longest is 184.

Fixed by matching the model book at `C:/github/iris-book`, which had solved this already:

| | Before | Now |
| --- | --- | --- |
| Page | 6 by 9 inches, 120mm measure | A4, 24/20/22mm margins, 170mm measure |
| Body | 11pt at 1.55 | 10.6pt at 1.72 |
| Code | `overflow-x: auto`, `white-space: pre` | `white-space: pre-wrap`, `overflow-wrap: break-word` |
| Breaks | none | `orphans: 4`, `widows: 4`, so a listing never strands a closing brace |
| Ligatures | on | off, so `:=` stays two characters |
| Tables | could overflow the same way | `table-layout: fixed`, `overflow-wrap: break-word` |

121 pages instead of 210, and every listing readable end to end. Verified by screenshotting
the paginated page holding the longest signature and reading it, which is what should have
happened the first time.

The rule is now written down in `book/README_EBOOK.md` under "Page size and code, which are
one decision", including the arithmetic for re-measuring if the page size ever changes and
the instruction to look at a page with a long listing afterwards, because no check catches
this class of mistake.

## The release is v0.2.0

Your call, replacing v0.2.0. Nineteen references across thirteen files were renumbered, and
the changelog gained a date and a paragraph on what going to 1.0 commits to: the surface has
been audited symbol by symbol, and under semantic versioning the breaking changes in this
release are the last until 2.0.

One thing the blanket rename broke and the build caught: chapter 12's contents anchor read
`#behaviour-that-changed-in-v020`, which contains no literal "v0.2.0", so it was missed while
its heading changed. The generator refused the build until it matched. That is the anchor
check earning its place.
