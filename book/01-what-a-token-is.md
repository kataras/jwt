# Chapter 1: What a Token Is

A JSON Web Token is a string with two dots in it. Before any of this package's API makes
sense, it is worth taking one apart by hand, because almost every mistake people make with
tokens comes from a wrong mental model of what those three pieces are and which of them the
signature covers. This chapter builds the format from nothing, decodes a real token
character by character, and then states precisely what verifying one does and does not
tell you.

## Table of Contents

- [Three segments and two dots](#three-segments-and-two-dots)
- [Why base64url and not base64](#why-base64url-and-not-base64)
- [Taking a token apart in Go](#taking-a-token-apart-in-go)
- [What the signature covers](#what-the-signature-covers)
- [What verifying proves, and what it does not](#what-verifying-proves-and-what-it-does-not)
- [The compact form is not encryption](#the-compact-form-is-not-encryption)
- [Summary](#summary)
- [Further Reading](#further-reading)

## Three segments and two dots

Here is a complete token, produced by this package with the shared key
`sercrethatmaycontainch@r$`:

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImthdGFyYXMifQ.HxPZbhkeH0DtRAOJH_1F0YnbmxJvNQiaLzFHBQ-QLtc
```

Split it on the dots and you get three parts:

| Part | Decoded | What it is |
| --- | --- | --- |
| `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9` | `{"alg":"HS256","typ":"JWT"}` | The header. Says how the token was signed. |
| `eyJ1c2VybmFtZSI6ImthdGFyYXMifQ` | `{"username":"kataras"}` | The payload. Your claims. |
| `HxPZbhkeH0DtRAOJH_1F0YnbmxJvNQiaLzFHBQ-QLtc` | 32 raw bytes | The signature. |

The first two are JSON documents that have been base64url encoded. The third is not text at
all: it is the raw output of a signing function, encoded the same way so it survives being
put in a URL or an HTTP header.

That is the entire compact serialization. There is no length prefix, no version marker and
no envelope. A parser splits on `.`, expects exactly three parts, and goes from there.

## Why base64url and not base64

Standard base64 uses `+` and `/` in its alphabet and pads with `=`. All three characters
mean something in a URL, so a token pasted into a query string or a cookie would need
escaping, and something in the chain would eventually escape it twice.

Base64url swaps `+` for `-` and `/` for `_`, and JWT drops the padding entirely. RFC 7515
requires that: the padding carries no information, since the length of the encoded text
already tells a decoder how many bytes came in.

Dropping the padding is why decoding a segment is slightly more than a library call. The
standard decoder wants input whose length is a multiple of four. This package handles it
by removing padding rather than adding it:

```go
func Base64Decode(src []byte) ([]byte, error) {
	src = bytes.TrimRight(src, padStr)

	buf := make([]byte, base64.RawURLEncoding.DecodedLen(len(src)))
	n, err := base64.RawURLEncoding.Decode(buf, src)
	return buf[:n], err
}
```

The obvious alternative, appending `=` characters until the length divides by four, is a
trap, and this package fell into it for years. Chapter 12 explains what went wrong: the
short version is that `bytes.Split` hands back a final segment that still owns the whole
token's spare capacity, so appending to it writes past the end of the caller's buffer.
Trimming has no such problem, needs no allocation, and turned out to be faster.

## Taking a token apart in Go

You do not have to do any of that by hand. `Decode` parses a token without checking
anything:

```go
unverified, err := jwt.Decode(token)
if err != nil {
	return err
}

fmt.Printf("header:  %s\n", unverified.Header)
fmt.Printf("payload: %s\n", unverified.Payload)
```

```text
header:  {"alg":"HS256","typ":"JWT"}
payload: {"username":"kataras"}
```

The type it returns is called `UnverifiedToken`, and the name is doing real work. Nothing
in that struct has been checked. The signature was decoded but not tested. The header says
`HS256` because the sender wrote `HS256`, not because anybody agreed.

Use `Decode` when you need to look at a token before you can verify it: reading the `kid`
to work out which key to fetch, or logging which issuer a rejected token claimed. Do not
use it to read claims you are going to act on.

## What the signature covers

This is the part worth being precise about. The signature is computed over the header and
the payload **in their encoded form**, joined by a dot:

```text
signature = Sign(key, base64url(header) + "." + base64url(payload))
```

Three consequences follow, and each one is a bug somebody has shipped.

**The signature covers the header.** An attacker cannot change `alg` without invalidating
it. That is what makes the header trustworthy after verification, and it is why this
package will carry a verified header forward into an enriched token but never an
unverified one.

**The signature covers the encoded bytes, not the decoded JSON.** Two payloads that parse
to the same object can have different signatures, and one signature is valid for exactly
one byte sequence. You cannot re-serialize a payload and keep the signature. That is why
adding a claim to an existing token means signing a new token, which is what `Enrich`
does.

**The signature covers nothing else.** Not the transport, not the time you received the
token, not who sent it to you. A signed token that is valid for somebody else is still a
valid token when it arrives from an attacker who stole it.

## What verifying proves, and what it does not

When `Verify` returns without an error, you have learned exactly one thing:

> Somebody holding the key you supplied produced these exact header and payload bytes.

That is worth a lot, and it is less than people assume. Here is the same statement turned
into the questions it does and does not answer.

| Question | Does verification answer it? |
| --- | --- |
| Were these bytes produced by a holder of the key? | Yes. |
| Have the claims been modified since? | No, they have not. Verification proves that. |
| Is the token within its validity window? | Only because this package also checks `exp` and `nbf`. That is claim validation, not signature verification. |
| Was it issued for me? | No. Check `aud` yourself, or with `Expected`. |
| Was it issued by who I think? | No. Check `iss`. |
| Is the person presenting it the person it was issued to? | No. Nothing in a bearer token can tell you that. |
| Has it been revoked? | No. See Chapter 9. |

The last two are where real incidents come from. A JWT is a bearer credential: possession
is the whole authorization. If it leaks, whoever holds it is you, until it expires.

## The compact form is not encryption

Base64 is an encoding, not a cipher. Anyone holding a token can read its payload with a
one-line command:

```sh
echo 'eyJ1c2VybmFtZSI6ImthdGFyYXMifQ' | base64 -d
```

```text
{"username":"kataras"}
```

People put things in payloads that they would not put in a URL, on the reasoning that the
token looks opaque. It is not opaque. Treat the payload as public. Put an identifier in it
and look the rest up on your side.

If you genuinely need the payload hidden from the person carrying it, Chapter 11 covers the
package's AES-GCM support, along with the cases where it does not help.

## Summary

A JWT is three base64url segments separated by dots: a header saying how it was signed, a
payload of claims, and a signature over the first two in their encoded form. Base64url
exists so the result survives a URL, and JWT drops the padding, which is why decoding trims
rather than pads.

Verification proves that a holder of your key produced those exact bytes. It does not
prove the token is for you, is from who you expect, is still wanted, or is being presented
by its owner. Those are separate checks, and the rest of this book is largely about making
them.

The payload is readable by anyone holding the token. Encoding is not encryption.

## Further Reading

- [RFC 7519: JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519): the format itself,
  including the registered claim names.
- [RFC 7515: JSON Web Signature](https://www.rfc-editor.org/rfc/rfc7515): the compact
  serialization and exactly what the signing input is. Section 5.1 is the one to read.
- [RFC 4648 section 5](https://www.rfc-editor.org/rfc/rfc4648#section-5): base64url, and
  why the padding is optional.
- [jwt.io](https://jwt.io): paste a token in and see it split. Useful for a token you did
  not produce, and a good demonstration that the payload is public.

---

**Next Chapter**: [Signing and Verifying](02-signing-and-verifying.md) - The two functions you will use most, and why the algorithm is an argument rather than something read from the token.
