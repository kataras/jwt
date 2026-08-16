# Epilogue

The library this book describes is about four thousand lines of Go with no dependencies. It
does one thing. That should make it simple, and mostly it is: `Sign` and `Verify` are two
functions, and the format is three base64url segments joined by dots.

What is not simple is everything around those two functions, and that is what took most of
the pages. Which algorithm, and therefore who can mint a token as well as read one. Which
key, and what happens on the day it has to be replaced without a maintenance window. What
a claim means when a service in another language reads the same bytes. What to do about a
session that has to end before its token does.

## The pattern worth taking away

Almost every defect this package has had, and there have been a number, was the same shape:
something reported success while failing.

A revocation that returned `nil` and then evaporated on the next garbage collection tick. A
build tag that was documented for years and had never compiled. A key set generator that
returned an error for every ECDSA key, so a service published a `/.well-known/jwks.json`
with a key missing from it. An expiry claim that overflowed to a negative number, failed a
greater-than-zero test, and produced a token that never expired. An enrichment path that
signed an attacker's header with your private key and handed back a perfectly valid token.

None of those threw. None of them showed up in a log. Each one needed somebody to sit down
with the source and ask what the code does rather than what it says it does.

If you take one habit from this book, take that one. When something in an authentication
path looks like it worked, check what it actually did. The failures that announce
themselves are the cheap ones.

## What this package is not going to do for you

It signs and verifies tokens. It does not decide who your users are, what they may do, or
whether a token that verifies should be honoured. A signature proves that a holder of a key
produced some bytes. Everything from there is yours: the audience check, the issuer check,
the revocation list, the session model, and the decision about what a claim entitles
somebody to.

It also will not stop you putting a password in a payload, granting a token a year of life,
or sharing an HMAC key with a service you do not control. Chapter 12 lists the places where
the library is quieter about that than it might be.

## Contributing

The repository is at `github.com/kataras/jwt`. The test suite is hermetic and runs in about
four seconds, so there is no excuse for a change without a test. If you find something in
this book that does not match the source, the source is right and the book is wrong: open
an issue and say which page.

Two things are worth knowing before you send a change. The library keeps no dependencies,
and that is not negotiable; the book and the brand kit are separate modules for exactly
that reason. And performance is a feature here, so a change that adds an allocation to
`Sign` or `Verify` needs to say what it buys.

## Thanks

To everyone who filed an issue against this package with a reproducer attached, which is
rarer and more useful than it sounds. To the authors of RFC 7515, 7517, 7518 and 7519, who
wrote specifications precise enough to implement from and honest enough to say where the
danger is. And to the people who ran this code in production and reported what broke, which
is the only way any of the defects in chapter 12 were ever found.

Go build something, and give your tokens an expiry.
