# Chapter 9: Revoking Tokens

A signed token is a promise you cannot take back. Once it leaves your server, every service
holding your verification key will accept it until its expiry passes, and nothing in the
format lets you change your mind. That is the price of a credential that verifies without a
round trip. This chapter covers what to do when you need to change your mind anyway: why
short lifetimes are the first answer, what a blocklist costs, and the two ways people get
one wrong.

## Table of Contents

- [Why a token cannot be taken back](#why-a-token-cannot-be-taken-back)
- [Short lifetimes come first](#short-lifetimes-come-first)
- [The blocklist](#the-blocklist)
- [Choosing the key](#choosing-the-key)
- [Tokens with no expiry](#tokens-with-no-expiry)
- [Where it sits in the validator chain](#where-it-sits-in-the-validator-chain)
- [A distributed blocklist](#a-distributed-blocklist)
- [Revoking a refresh token with its access token](#revoking-a-refresh-token-with-its-access-token)
- [Summary](#summary)
- [Further Reading](#further-reading)

## Why a token cannot be taken back

Verification is a local computation. A service holding the public key checks a signature and
reads some claims, and at no point does it ask you whether the token is still wanted. That
is the whole appeal: no database lookup, no network call, no shared session store.

It is also the whole problem. When a user logs out, when an account is suspended, when a
laptop is stolen, the tokens already issued keep working. Deleting the token from the
client is a request, not a guarantee: whoever has a copy still has a valid credential.

There is no revocation in RFC 7519, and there could not be. Anything that let an issuer
withdraw a token would require the verifier to ask, and a verifier that asks is a session
store with extra steps.

## Short lifetimes come first

The cheapest answer is to make the window small. A token that lives fifteen minutes is a
credential an attacker can use for at most fifteen minutes, and no infrastructure is
required to achieve that:

```go
token, err := jwt.Sign(jwt.HS256, key, claims, jwt.MaxAge(15*time.Minute))
```

This is not a complete answer, and it is worth being honest about why. Fifteen minutes is a
long time if the token grants a wire transfer. It is also the window during which a
suspended account still works, which is difficult to explain to whoever suspended it.

What short lifetimes do is bound the damage and reduce how often you need anything else.
Reach for a blocklist for the cases the window does not cover, not for every logout.

## The blocklist

A blocklist is a set of tokens the server refuses even though they still verify. This
package ships an in-memory one:

```go
blocklist := jwt.NewBlocklist(1 * time.Hour)
defer blocklist.Close()

// On logout.
verifiedToken, err := jwt.Verify(jwt.HS256, key, token)
if err != nil {
	return err
}

if err = blocklist.InvalidateToken(verifiedToken.Token, verifiedToken.StandardClaims); err != nil {
	return err
}

// On every subsequent request. Blocklist implements TokenValidator.
verifiedToken, err = jwt.Verify(jwt.HS256, key, token, blocklist)
// err is now jwt.ErrBlocked
```

The argument to `NewBlocklist` is the garbage collection interval, not a lifetime. Entries
are removed once the token they refer to has expired on its own, because after that point
the signature check rejects it anyway and the entry is dead weight. Pass zero to disable the
background sweep and call `GC` yourself.

`NewBlocklistContext` takes a context if you would rather stop the goroutine that way.
`Close` stops it either way, and matters more than it looks: `NewBlocklist` passes
`context.Background()`, so without `Close` the goroutine and its ticker live for as long as
the process. That is fine for one blocklist created at startup and wrong for one created per
test or per tenant.

The rest of the surface is small:

| Method | What it does |
| --- | --- |
| `InvalidateToken(token []byte, c Claims) error` | Adds an entry. Returns `ErrMissing` for an empty token. |
| `ValidateToken(token []byte, c Claims, err error) error` | The `TokenValidator` implementation. Returns `ErrBlocked` when the entry is present. |
| `Has(key string) (bool, error)` | Whether a key is blocked. |
| `Del(key string) error` | Removes an entry. |
| `Count() (int64, error)` | How many entries are held. |
| `GC() int` | Runs one sweep and returns how many entries it removed. |

## Choosing the key

An entry is stored under a key derived from the token, and which key you use is the decision
that matters most here.

```go
func DefaultBlocklistKey(token []byte, c Claims) string {
	if c.ID != "" {
		return c.ID
	}

	return BytesToString(token)
}
```

The `jti` claim when the token has one, and the whole token otherwise. **Give every token a
`jti`.** The fallback works, and it keeps a complete bearer credential, signature included,
in memory for as long as the entry lives. A memory dump of a process holding a hundred
blocked sessions is a hundred usable tokens.

```go
token, err := jwt.Sign(jwt.HS256, key, claims,
	jwt.MaxAge(15*time.Minute),
	jwt.ID(uuid.NewString()),
)
```

Replace `Blocklist.GetKey` if you want a different scheme, and call
`DefaultBlocklistKey` rather than reimplementing it. That advice is not theoretical. A
storage backend written against this package returned `c.ID` unconditionally, without the
fallback. Every token without a `jti` therefore mapped to the empty string, so revoking one
session wrote to the key `""` and the existence check for every other session without a
`jti` read from `""`. One logout blocked every session in the system.

The in-memory `Blocklist` used to fail the same way, only more quietly. `Has` refuses an
empty key with `ErrMissing`, so an entry stored under one matched nothing: `InvalidateToken`
returned `nil`, the entry sat in the map, and `ValidateToken` let the token straight through.
A revocation that reports success and does nothing is worse than one that fails, so
`InvalidateToken` now refuses an empty key and says which two things to do about it.

`GetKey` and `Clock` are exported fields read outside the mutex, so set them before the
blocklist is in use, not while requests are arriving. Both have fallbacks inside the type, so
a zero-value `Blocklist` works rather than panicking on a nil field.

## Tokens with no expiry

An entry is stored with the token's expiry, and swept once that time passes. A token with no
`exp` has no such time, and the obvious implementation stores a zero.

That is what this package did, and it meant `InvalidateToken` returned `nil` and the entry
was deleted on the very next sweep, because a zero expiry reads as "expired in 1970". The
caller was told the session was revoked. A tick later it was live again, and nothing
anywhere reported a problem.

Such entries are now stored as never expiring, and `GC` skips them. That is the only answer
consistent with the token: one that never expires needs a revocation that never expires.

The consequence is a memory cost you should know about. Those entries are never collected,
so the blocklist grows with the number of revoked non-expiring tokens and never shrinks. If
that worries you, the fix is upstream: give tokens an expiry. `RequireExpiry` on the
verifying side turns the assumption into a check.

## Where it sits in the validator chain

Chapter 8 covered the rule: `Verify` runs validators in order and stops at the first one
that returns an error. A blocklist is a validator, so its position decides what it sees.

Put it last, after any validator that might reject the token for a cheaper reason:

```go
verifiedToken, err := jwt.Verify(jwt.HS256, key, token,
	jwt.Skew(time.Minute),
	jwt.Expected{Issuer: "auth.example.com"},
	blocklist,
)
```

There is a reason beyond tidiness. A blocklist lookup may be a network call to Redis, and an
expired token does not need one. Ordering the cheap checks first means a flood of expired
tokens costs you nothing downstream.

`ValidateToken` also cleans up after itself. When it is the first validator and the token
has genuinely expired, it removes the entry on the way past and returns `ErrExpired`
unchanged, because the claim check refuses that token anyway. Revoking a token and then
verifying it after expiry takes `Count` from one back to zero, which is worth knowing before
it surprises you on a graph.

## A distributed blocklist

The in-memory blocklist is per process. Two instances behind a load balancer do not share
one, so a logout handled by instance A does not stop instance B. For anything beyond a
single process you need shared storage, and this package gives you the interface rather than
the implementation:

```go
type TokenBlocklist interface {
	TokenValidator

	InvalidateToken(token []byte, c Claims) error
	Del(key string) error
	Has(key string) (bool, error)
	Count() (int64, error)
}
```

Accept that rather than `*jwt.Blocklist`, and an in-memory blocklist and a Redis one become
interchangeable. Here is the shape of a Redis-backed implementation:

```go
type RedisBlocklist struct {
	client *redis.Client
	prefix string
	Clock  func() time.Time
	GetKey func(token []byte, c jwt.Claims) string
}

func (b *RedisBlocklist) key(token []byte, c jwt.Claims) string {
	get := b.GetKey
	if get == nil {
		get = jwt.DefaultBlocklistKey // not a reimplementation
	}

	return b.prefix + get(token, c)
}

func (b *RedisBlocklist) InvalidateToken(token []byte, c jwt.Claims) error {
	if len(token) == 0 {
		return jwt.ErrMissing
	}

	// Let the store expire the entry rather than sweeping it yourself. A token with no
	// expiry gets no TTL at all, for the reason in the previous section.
	var ttl time.Duration
	if c.Expiry > 0 {
		ttl = time.Until(time.Unix(c.Expiry, 0))
		if ttl <= 0 {
			return nil // already expired; the claim check refuses it anyway
		}
	}

	return b.client.Set(context.Background(), b.key(token, c), 1, ttl).Err()
}

func (b *RedisBlocklist) ValidateToken(token []byte, c jwt.Claims, err error) error {
	if err != nil {
		if errors.Is(err, jwt.ErrExpired) {
			_ = b.Del(b.key(token, c))
		}

		return err
	}

	blocked, err := b.Has(b.key(token, c))
	if err != nil {
		// Decide this deliberately. See below.
		return err
	}
	if blocked {
		return jwt.ErrBlocked
	}

	return nil
}
```

Three things to get right, and the third is the one people argue about.

**Use `DefaultBlocklistKey`.** The outage described earlier came from reimplementing it.

**Let the store handle expiry.** A Redis TTL removes the entry for you, and no sweep is
needed. A token with no expiry gets no TTL, which is the same decision the in-memory version
makes.

**Decide what happens when the store is unreachable.** Returning the error fails closed:
every request is refused while Redis is down, including from users who were never revoked.
Returning `nil` fails open: everything works, and revoked sessions come back to life for the
duration of the outage. Neither is correct in general. Pick one on purpose, write down why,
and make sure the choice is visible in a dashboard rather than buried in a helper.

## Revoking a refresh token with its access token

`SignPair` links the two halves: the refresh token's `origin_jti` names the access token's
`jti`. That link exists for this chapter.

Revoking an access token on its own accomplishes little if the refresh token that mints its
replacement is still good. With the link, one lookup finds the other:

```go
pair, err := jwt.SignPair(jwt.HS256, key, claims, jwt.PairOptions{
	AccessOptions:  []jwt.SignOption{jwt.MaxAge(15 * time.Minute)},
	RefreshOptions: []jwt.SignOption{jwt.MaxAge(7 * 24 * time.Hour)},
})

// pair.RefreshClaims.OriginID == pair.AccessClaims.ID
```

Store the pairing when you issue it, and on revocation block both identifiers. The
alternative, blocking only what the user presented, leaves whichever half they did not
present working.

## Summary

A JWT verifies locally, which is why it is fast and why it cannot be withdrawn. Short
lifetimes are the first answer and bound the damage without any infrastructure. A blocklist
covers what the window does not, at the cost of a lookup on every request and a store to
keep.

Give every token a `jti`, or the entry key is the whole token and you are keeping bearer
credentials in memory. Call `DefaultBlocklistKey` rather than reimplementing it, because
returning the `jti` unconditionally maps every token without one to the same empty key and
one logout blocks everybody.

A revocation for a token with no expiry is kept forever, because the token is valid forever.
That is correct and it is a memory cost, and the fix is to give tokens an expiry rather than
to shorten the revocation.

Put the blocklist last in the validator chain, so the cheap checks run first, and decide on
purpose what happens when a shared store is unreachable.

## Further Reading

- [RFC 7519 section 4.1.7](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7): the `jti`
  claim, and the uniqueness it is expected to have.
- [RFC 7009: OAuth 2.0 Token Revocation](https://www.rfc-editor.org/rfc/rfc7009): the
  endpoint shape for accepting a revocation request, if you are exposing one.
- [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068): a profile for JWT access tokens in
  OAuth 2.0, including what it says about token lifetime.
- [sync.RWMutex](https://pkg.go.dev/sync#RWMutex): what the in-memory blocklist uses, and
  why a sweep that releases the lock between reading and deleting can lose a write.

---

**Next Chapter**: [Tokens over HTTP](10-tokens-over-http.md) - Getting a token out of a request, and issuing an access and refresh pair.
