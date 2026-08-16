# Preface

A JSON Web Token is three pieces of base64url text joined by dots. That is the whole
format. Everything difficult about tokens happens around that format: which algorithm you
pinned, which key you verified with, whether the claim you read was the one that was
signed, and what you do on the day a key has to be replaced while requests keep arriving.

This book is about `github.com/kataras/jwt`, a JWT and JWKS implementation for Go with no
dependencies. It covers what the package does, and it spends at least as long on why the
API is shaped the way it is. An API you can predict is worth more than one you have to
look up, and the only way to make it predictable is to say what it was worried about.

## Who this is for

You write Go, and something in your system hands out tokens or accepts them. You do not
need to have read RFC 7519. Chapter 1 builds the format from nothing, and every chapter
after that assumes only what came before it.

If you already know JWT well, skip to Chapter 5 for the algorithm trade-offs, Chapter 7 for
key rotation, or Chapter 12, which is the honest list of this package's sharp edges.

## What this book is not

It is not a reference. The reference is `go doc`, and it is generated from the source,
which means it cannot drift. This book is the part `go doc` cannot give you: the order to
do things in, the reason a default is what it is, and the failure that made somebody choose
it.

It is also not a security course. It will tell you that verifying a signature proves who
wrote a token and nothing else about whether you should trust its contents, and it will
show you the code that gets that wrong. It will not teach you threat modelling.

## How the code in here was checked

Every signature quoted in this book was compared against the package source, not
remembered. That sounds like a low bar. It is not: the package's own documentation
contained a dozen examples that could not compile, including four that showed the wrong
number of return values and three that referenced a type which does not exist. Prose is not
compiled, so nothing catches this for you.

Where a chapter says a call returns a particular error, that error was produced and read.
Where it quotes a benchmark number, that benchmark was run on the machine named beside it.

## The shape of the book

Chapters 1 to 4 are the parts every user needs: the format, signing and verifying, claims,
and time. Chapters 5 to 7 are about keys, which is where real systems spend their
difficulty. Chapters 8 to 11 cover validation, revocation, HTTP, and payload encryption.
Chapter 12 is the sharp edges. Chapters 13 and 14 are testing and performance.

Read 1 to 4 in order. After that, take what you need.

## A note on the word secure

This book avoids calling anything secure. A token is signed, or it is not. A signature
verifies under a key, or it does not. A claim was covered by that signature, or it was not.
Those are checkable. "Secure" is a summary of somebody's judgement about a whole system,
and a library cannot make that judgement for you.

Where this book does make a recommendation, it says what the recommendation protects
against and what it costs. You can then disagree with it on purpose rather than by
accident.

---

**Next Chapter**: [What a Token Is](01-what-a-token-is.md) - The three segments, what base64url is doing there, and what a signature actually proves.
