# Chapter 4: Expiry and Time

A bearer token is valid until it is not, and the only thing deciding when that moment
arrives is a number in the payload. RFC 7519 makes every one of the time claims optional,
which means the default state of a JWT is permanent. This chapter covers the three time
claims, the exact rules this package applies to them, the two validators that exist because
clocks disagree, and one function whose name points the opposite way from what it does.

## Table of Contents

- [The three time claims](#the-three-time-claims)
- [Why zero means absent](#why-zero-means-absent)
- [Setting a lifetime with MaxAge](#setting-a-lifetime-with-maxage)
- [Requiring an expiry](#requiring-an-expiry)
- [Clock skew and the order of validators](#clock-skew-and-the-order-of-validators)
- [Leeway is stricter than it sounds](#leeway-is-stricter-than-it-sounds)
- [Replacing the clock in tests](#replacing-the-clock-in-tests)
- [Reading time off a verified token](#reading-time-off-a-verified-token)
- [Choosing lifetimes](#choosing-lifetimes)
- [Summary](#summary)
- [Further Reading](#further-reading)

## The three time claims

RFC 7519 registers three claims that carry a time, all of them as seconds since the Unix
epoch, and all three are listed as optional.

| Claim | Name | Meaning | Section |
| --- | --- | --- | --- |
| `exp` | Expiration Time | When the token stops being valid. | 4.1.4 |
| `nbf` | Not Before | When the token starts being valid. | 4.1.5 |
| `iat` | Issued At | When the token was created. | 4.1.6 |

In this package they are three fields on `Claims`:

```go
type Claims struct {
	NotBefore int64 `json:"nbf,omitempty"`
	IssuedAt  int64 `json:"iat,omitempty"`
	Expiry    int64 `json:"exp,omitempty"`
	// ... iss, sub, aud, jti, origin_jti
}
```

`exp` is the one that matters for security. It puts a ceiling on the damage a leaked token
can do, because a stolen bearer credential is the holder's credential until it expires and
nothing about the token itself can tell you it was stolen.

`nbf` is for tokens minted ahead of the moment they are supposed to work: a subscription
that starts at midnight, a batch job whose credentials are prepared in the previous run.
Most systems never set it.

`iat` is metadata rather than a control. It tells you how old a token is and lets a verifier
notice a clock that is badly wrong. It bounds nothing by itself.

`Verify` checks all three when they are present. There is no option to turn that off, and
the check runs after the signature, so the values being checked are values your key covered.

## Why zero means absent

Read `validateClaims` in `claims.go`. It is short, and every line is a decision:

```go
func validateClaims(t time.Time, claims Claims) error {
	now := t.Round(time.Second).Unix()

	if claims.NotBefore != 0 {
		if now < claims.NotBefore {
			return ErrNotValidYet
		}
	}

	if claims.IssuedAt != 0 {
		if now < claims.IssuedAt {
			return ErrIssuedInTheFuture
		}
	}

	if claims.Expiry != 0 {
		if now > claims.Expiry {
			return ErrExpired
		}
	}

	return nil
}
```

The three fields are `int64` tagged `omitempty`. That tag makes a `Claims` value with no
expiry serialize to a payload with no `exp` key, and it also makes zero unrepresentable as a
real value: nothing in the round trip distinguishes "the issuer did not set this" from "the
issuer set this to 1970-01-01T00:00:00Z". So zero is read as absent and the claim is
skipped.

Every other value is present and gets checked, negative ones included. A token carrying
`"exp": -1` expired one second before the epoch, and `now > claims.Expiry` is true for any
clock set after 1969, so `Verify` returns `ErrExpired`.

Both comparisons are strict, and the reference time is rounded to the nearest second. A
token is therefore accepted from the exact second named by its `nbf`, which is what RFC 7519
asks for, and still accepted during the exact second named by its `exp`, which is a second
more generous than a strict reading of "the current time MUST be before `exp`". The RFC
allows small leeway of this kind. In practice it means every window is a whole number of
seconds wide, and sub-second precision does not exist anywhere in this format.

That sounds obvious and it was not always the code. The test used to be `claims.Expiry > 0`,
which reads as "if an expiry was set" and behaves as "if the expiry is after 1970". Under
that rule a negative `exp` counted as no expiry at all, so a token that should have been
rejected outright verified and stayed valid forever. `toUnix` reaches the same place from
another direction: it converts a JSON number to `int64`, and a float too large for `int64`
used to land on the most negative value the type can hold, so an `"exp"` of `1e400` produced
an immortal token. Both are fixed, and `toUnix` now returns an error wrapped in
`ErrTokenForm` for anything out of range.

**One asymmetry to know about.** `Claims.ApplyClaims`, which runs when you pass a `Claims`
value as a `SignOption`, copies each timing field only `if v > 0`. A template `Claims`
carrying a negative `Expiry` is therefore ignored on the way in, while a token arriving with
a negative `exp` is treated as expired on the way out.

## Setting a lifetime with MaxAge

You will rarely fill `Expiry` in by hand:

```go
token, err := jwt.Sign(jwt.HS256, key, claims, jwt.MaxAge(15*time.Minute))
```

`MaxAge` sets two claims, not one:

```go
func MaxAge(maxAge time.Duration) SignOptionFunc {
	if maxAge <= time.Second {
		return NoMaxAge
	}

	return func(c *Claims) {
		now := Clock()
		c.Expiry = now.Add(maxAge).Unix()
		c.IssuedAt = now.Unix()
	}
}
```

`iat` comes along with `exp` because the two are read together. An `exp` with no `iat` tells
a reader when the token dies but not how long it was meant to live, which is what
`Claims.Age()` reports.

Now the guard at the top. Any duration of one second or less returns `NoMaxAge`, and
`NoMaxAge` is not a no-op:

```go
var NoMaxAge SignOptionFunc = func(c *Claims) {
	c.Expiry = 0
	c.IssuedAt = 0
}
```

It zeroes both fields, `omitempty` drops them, and the token goes out with no `exp` and no
`iat`. State that plainly, because it is the sentence people need: **a zero `MaxAge` in a
configuration file produces permanent tokens, and no call in the chain returns an error.**
`Sign` succeeds. `Verify` succeeds, tomorrow and next year. Nothing logs anything.

The route into that is short. A `KeyConfiguration` carries a `MaxAge time.Duration` field
with `json`, `yaml`, `toml` and `ini` tags, and `Keys.SignToken` applies it only under `if
k.MaxAge > 0`. Leave `MaxAge` out of the YAML, or write `MaxAge: 0`, and the option is never
added. Write `MaxAge: 1s` and the option is added and then erases itself. Two different
mistakes, one result.

If your claims are a `Map` rather than a struct, the equivalent is
`func MaxAgeMap(maxAge time.Duration, claims Map)`, which mutates the map in place and
returns nothing:

```go
claims := jwt.Map{"user_id": "12345", "role": "admin"}
jwt.MaxAgeMap(15*time.Minute, claims)

token, err := jwt.Sign(jwt.HS256, key, claims)
```

Two differences from `MaxAge`. It will not overwrite an `exp` already in the map, so a
caller who set one keeps it. And for a duration of one second or less it returns without
touching the map rather than zeroing anything, so the failure here is "no expiry was added"
rather than "an expiry was removed". Both end at a token with no `exp`.

## Requiring an expiry

RFC 7519 leaves `exp` optional and this package follows the RFC. If you want the stricter
rule, ask for it:

```go
verifiedToken, err := jwt.Verify(jwt.HS256, key, token, jwt.RequireExpiry)
```

`RequireExpiry` is a `TokenValidatorFunc` value, not a function returning one, so it takes
no arguments. Its body does three things in order: return any error that arrived from
earlier validation, return `ErrMissingExpiry` if `standardClaims.Expiry == 0`, otherwise
return nil. That first step matters. A token that has genuinely expired already failed with
`ErrExpired`, which this validator passes through, so it only ever sees the missing case.
The error message is `jwt: token has no expiry`.

Add it wherever you accept tokens you did not mint, and to your own issuer's verification
too, because that is what catches the configuration mistake above on the day it ships rather
than on the day somebody audits the key store.

There is a second reason, about revocation. A blocklist entry has to be kept until the token
would have expired anyway, at which point it can be dropped. A token with no expiry has no
such point, so its revocation record can never be collected. Chapter 9 goes into it.

## Clock skew and the order of validators

Two machines rarely agree on the time to the second. An issuer whose clock runs two minutes
fast mints a token whose `iat` is in the future from the verifier's point of view, and
`validateClaims` rejects it with `ErrIssuedInTheFuture` even though nothing is wrong with
it. There are two validators for this, and the difference between them is not obvious from
the names.

```go
func Future(dur time.Duration) TokenValidatorFunc
func Skew(d time.Duration) TokenValidatorFunc
```

`Future` opens with `if errors.Is(err, ErrIssuedInTheFuture)` and does nothing for any other
error. It rescues `iat`, and only `iat`. Now look again at `validateClaims`: it checks `nbf`
first and returns as soon as that check fails. An issuer that sets `nbf` equal to `iat`,
which several do, produces a skewed token that fails with `ErrNotValidYet`, and `Future`
passes that error straight through. The rescue never happens.

This is not hypothetical. Four call sites across two services depended on `Future` and
worked only because the identity provider they talked to happens to omit `nbf`. A change at
the provider would have broken all four at once.

`Skew(d)` is the one to reach for:

```go
verifiedToken, err := jwt.Verify(jwt.HS256, key, token, jwt.Skew(2*time.Minute))
```

It switches on the error it was handed and accepts either `ErrNotValidYet` or
`ErrIssuedInTheFuture` when the claim falls within `d` of now. A non-positive `d` passes the
error through unchanged, so `Skew(0)` is a safe no-op rather than a validator that accepts
everything.

Tolerance in the other direction is deliberately not offered. There is no option to accept a
token that expired thirty seconds ago. Extending the life of a credential that has run out
is a policy decision about your system, not a correction for a clock, and if you want it you
should write it where a reviewer can see it.

**Validator order is load-bearing.** `Verify` runs validators in the order you pass them,
handing each one the error the previous produced, and it breaks out of the loop at the first
validator that returns non-nil. A validator that rescues an error must therefore come before
one that would refuse it. Almost every built-in validator, `Expected` among them, opens with
`if err != nil { return err }`, which is the correct way to respect an earlier failure and
also the reason ordering matters:

```go
// Correct: Skew clears the skew error, then Expected checks the issuer.
jwt.Verify(alg, key, token, jwt.Skew(2*time.Minute), jwt.Expected{Issuer: "us"})

// Wrong: Expected returns ErrNotValidYet, Verify breaks, Skew never runs.
jwt.Verify(alg, key, token, jwt.Expected{Issuer: "us"}, jwt.Skew(2*time.Minute))
```

If you keep validators in a slice and want to append at a call site, `Validators` saves you
the conversion loop and preserves order:

```go
jwt.Verify(alg, key, token, jwt.Validators(app.Validators, jwt.Skew(time.Minute))...)
```

One consequence of the early return in `validateClaims` deserves a sentence. When `Skew`
clears an `nbf` failure, the `iat` and `exp` checks for that token never ran, because
`validateClaims` returned before reaching them. In practice that only matters for a token
whose `exp` is earlier than its `nbf`, which nobody meant to issue, but it is worth knowing
that a cleared error is a skipped check rather than a passed one.

## Leeway is stricter than it sounds

`Leeway` reads like a tolerance. It is the opposite.

```go
func Leeway(leeway time.Duration) TokenValidatorFunc
```

The whole of its logic is one comparison, guarded by `err == nil` and `Expiry > 0`:

```go
if Clock().Add(leeway).Round(time.Second).Unix() > standardClaims.Expiry {
	return ErrExpired
}
```

It moves the clock forward by `leeway` and then asks whether the token has expired. So
`jwt.Leeway(30 * time.Second)` rejects, with `ErrExpired`, any token that will expire within
the next thirty seconds. It narrows the acceptance window instead of widening it.

The name comes from the caller's problem rather than the token's. You are about to start
work that will take a while: a database transaction, a chain of calls to three services, a
batch that runs for twenty seconds. Beginning that with a credential that dies halfway
through leaves you with a partial write and a 401 you cannot retry. `Leeway` is how you
insist on a token with enough life left to finish. Note the two guards: it does nothing at
all for a token with no `exp`, and it never rescues an earlier error, only refuses.

## Replacing the clock in tests

Every time comparison in this package goes through one package-level variable:

```go
var Clock = time.Now
```

`validateClaims`, `MaxAge`, `MaxAgeMap`, `Leeway`, `Future`, `Skew` and `Claims.Timeleft`
all call it. Replace it and you control the package's idea of now, which is how you test
expiry without sleeping:

```go
func TestExpiredToken(t *testing.T) {
	original := jwt.Clock
	t.Cleanup(func() { jwt.Clock = original })

	base := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	jwt.Clock = func() time.Time { return base }

	token, err := jwt.Sign(jwt.HS256, key, jwt.Map{"sub": "user"}, jwt.MaxAge(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	jwt.Clock = func() time.Time { return base.Add(2 * time.Hour) } // past the expiry

	if _, err = jwt.Verify(jwt.HS256, key, token); !errors.Is(err, jwt.ErrExpired) {
		t.Fatalf("expected ErrExpired but got: %v", err)
	}
}
```

`t.Cleanup` is doing real work there. A test that leaves `Clock` pointing at a fixed instant
breaks every later test that expects real time, and the failure surfaces somewhere else
entirely.

**Set it once, at startup.** `Clock` is read without a lock, from whichever goroutine is
verifying, so assigning to it while requests are in flight is a data race and the race
detector will say so. That rules out swapping the clock in a test that runs in parallel with
others: keep those serial, or build the token you need from explicit `Claims` values and
leave the global alone. The same applies to `CompareHeader`, `ReadFile`, `Marshal`,
`Unmarshal` and `MaxTokenSize`.

## Reading time off a verified token

Three methods on `Claims` answer the questions you will actually ask:

```go
func (c Claims) Age() time.Duration
func (c Claims) ExpiresAt() time.Time
func (c Claims) Timeleft() time.Duration
```

`Age` is `exp` minus `iat`: the lifetime the issuer intended, not the time elapsed since
issuance. It does not consult the clock. With either claim missing it returns whatever the
subtraction produces, so check for zero before you trust it.

`ExpiresAt` converts `exp` to a `time.Time` at second precision. With no `exp` you get
`time.Unix(0, 0)`, the epoch, which is emphatically not "no expiry" if you feed it to a
comparison.

`Timeleft` is `exp` minus `Clock()`, so it is the one that moves. Positive means the token
is still good, negative means it has expired, and zero means either that it expires exactly
now or that there is no `exp` at all. Those last two are indistinguishable in the return
value, which is a good reason to pair it with `RequireExpiry`:

```go
verifiedToken, err := jwt.Verify(jwt.HS256, key, token, jwt.RequireExpiry)
if err != nil {
	return err
}

claims := verifiedToken.StandardClaims
if left := claims.Timeleft(); left < 2*time.Minute {
	log.Printf("token for %s expires at %s, %s left",
		claims.Subject, claims.ExpiresAt().Format(time.RFC3339), left)
}
```

`StandardClaims` is a field on `*VerifiedToken`, already parsed. Your own claims come out
separately through `verifiedToken.Claims(&dest)`.

## Choosing lifetimes

There is no correct number, but there is a shape, and it comes from one fact: you cannot
un-issue a JWT. Verification is a signature check and a clock comparison, neither of which
asks anything else, which is the whole reason a JWT scales and the reason a token stays good
until it expires whatever happens in between.

**Access tokens: minutes.** Five to fifteen is the usual range. This is the token that
travels on every request, gets logged by proxies, sits in browser memory, and shows up in
crash reports. A short lifetime gives a leak a deadline. The cost is refresh traffic and the
client-side machinery to handle a 401 mid-flight without losing the user's work.

**Refresh tokens: days to weeks.** Seven days is a common default. This token is presented
rarely, to one endpoint, and can be stored somewhere better guarded. The cost is that it
becomes the thing worth stealing, which is why it should be revocable: keep its `jti` and
check a blocklist when it is presented. Chapter 9 covers that, and the pairing is common
enough that the package ships a `TokenPair` type for it.

**Anything you cannot revoke: as short as you can stand.** For a token minted for one
operation, a machine-to-machine call or a signed download link, the lifetime should cover
the operation and no more.

**Permanent tokens: almost never.** If you need a credential that does not expire you also
need a way to revoke it, which means a lookup on every request, which means the JWT is
buying you nothing over an opaque random string in a database. Use the database.

One more number to set deliberately: the tolerance you pass to `Skew` should be smaller than
your shortest token lifetime, or you have quietly extended it. On hosts running NTP, a
minute or two is generous, and reaching for ten usually means a clock is broken somewhere
and the tolerance is hiding it.

## Summary

`exp`, `nbf` and `iat` are all optional in RFC 7519, so a token with none of them is a valid
token that never expires. `Verify` checks all three when they are present, after the
signature. Zero means absent, because `int64` plus `omitempty` leaves nothing else to mean
it. Every other value is checked, negative ones included, so `exp: -1` is expired rather
than unbounded.

`MaxAge(d)` sets both `exp` and `iat`, and for any `d` of one second or less it returns
`NoMaxAge`, which clears both. A zero `MaxAge` in a config file therefore yields permanent
tokens silently. `RequireExpiry` is the check that catches it, and it returns
`ErrMissingExpiry`.

For clock skew use `Skew(d)`, which covers `nbf` and `iat`. `Future(d)` covers only `iat`,
and since `validateClaims` returns at the first failed check it cannot rescue a token whose
issuer set `nbf`. Validators run in the order given and `Verify` stops at the first error,
so a rescuing validator must come first. `Leeway(d)` is stricter rather than looser: it
rejects tokens expiring within the next `d`.

`Clock` is a package variable, ideal for tests, read without a lock, so set it before
anything concurrent starts. `Age()`, `ExpiresAt()` and `Timeleft()` read the claims you have
already verified.

## Further Reading

- [RFC 7519 section 4.1.4](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4): the `exp`
  claim, including the sentence that makes it optional and the note about leeway between
  clocks. Sections [4.1.5](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5) and
  [4.1.6](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6) cover `nbf` and `iat`.
- [RFC 8725: JSON Web Token Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725):
  the operational advice RFC 7519 leaves out, including why a claim you did not validate is
  not a claim you know.
- [pkg.go.dev/github.com/kataras/jwt](https://pkg.go.dev/github.com/kataras/jwt): the
  generated reference for `MaxAge`, `Leeway`, `Skew`, `Future` and `RequireExpiry`.
- [pkg.go.dev/time#Duration](https://pkg.go.dev/time#Duration): what `2*time.Minute` is, and
  why a `time.Duration` written as a bare integer is nanoseconds.

---

**Next Chapter**: [Choosing an Algorithm](05-choosing-an-algorithm.md) - The six families, what each one costs, and the single question that decides between them.
