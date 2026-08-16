---
name: human-writing
description: Use when writing or editing any prose in this repository - the book's preface, its chapters and epilogue, the brand kit notes, the agent skill documents, the changelog, and the root README. Also use when editing a doc comment in a .go file here. Strips the tells of AI-drafted prose (em dashes as clause separators, "comprehensive", "robust", "leverage", "provides a flexible way to", contractions, templated Introduction and Conclusion sections) and rewrites in plain, direct, technical English. Triggers on "humanize", "human writing", "AI tells", "em dashes", "does this sound generated", "polish the book", or any edit to a .md file here.
---

# Human writing, for the jwt repository

This repository is read by people deciding whether to trust a security library with their
authentication. It has to sound like an engineer wrote it, because one did. Prose that
reads as generated invites the question of whether the code was too.

This skill is the standard, and `scripts/scan-tells.ps1` is the check.

## Scope

Every tracked markdown file: `book/**.md`, `brand/BRAND.md`, `skill/**/*.md` including this
one, and the root `README.md` and `CHANGELOG.md`. That is exactly the set the scanner's
`-Md` mode walks, so if the two disagree, one of them has a bug.

Untracked files are out of scope whatever they contain. Local agent configuration is not
published, so holding it to a standard no reader will ever see is wasted effort.

Doc comments in `.go` files are in scope for the standard but not for the scanner. The
scanner skips Go entirely, because separating a doc comment from a string literal from a
code sample inside a comment is more machinery than it is worth. Those are edited by hand,
and the rules below still apply to them.

`book/output/` is generated. Never edit it.

`book/README.md`, the preface, is the reference voice. When you are unsure how a sentence
should sound, read it.

## Scan before you write, and again after

```powershell
pwsh skill/human-writing/scripts/scan-tells.ps1 book/03-claims.md
pwsh skill/human-writing/scripts/scan-tells.ps1 -Md              # the whole corpus
pwsh skill/human-writing/scripts/scan-tells.ps1 -Md -Summary     # counts per rule
pwsh skill/human-writing/scripts/scan-tells.ps1 -Wrap book/      # long lines
```

```sh
skill/human-writing/scripts/scan-tells.sh --md --summary         # no pwsh needed
```

The scanner is fence aware. It never reports anything inside a fenced code block, and it
blanks inline code spans, link targets and bare URLs before matching, so an identifier or a
URL containing a double dash is not a finding. Exit code is 1 while findings remain.

**Zero findings is the bar for every file here.** There are no correct-in-context em dashes
in this repository.

The scanner is the only gate. No CI job runs it and no hook runs it: the hooks in this
repository sync artefacts, they do not lint prose. So finish every writing session with a
repository-wide pass, whatever single file you came to edit, and treat findings you did not
write as yours to fix.

## Em dashes: none in prose

An em dash between clauses is the strongest single tell in this corpus. There is always a
better mark. Pick by the job the dash was doing. The examples below are in code spans so
that this document passes its own scanner, which is the point of the escape hatch at the
bottom of this page:

| Job the dash was doing | Replacement | Example |
| --- | --- | --- |
| Interrupting appositive, a pair of dashes mid-sentence | A colon, or two sentences | `three failures — a nil key, a short nonce, a bad kid — each panicked` becomes `three failures panicked: a nil key, a short nonce and a bad kid` |
| Trailing explanation | A period and a new sentence | `Verify the token — the signature proves the key.` becomes `Verify the token. The signature proves the key.` |
| Definition or expansion | A colon | `` `exp` — the expiry claim `` becomes `` `exp` is the expiry claim `` |
| Subordinate aside | Parentheses | `the header (which is signed) cannot be edited` |
| A simple pause | A comma | |

Never substitute mechanically. Choose per sentence.

The en dash is fine in a numeric range (`16–48 px`). It is not a clause separator either.

## The rules

**Second person, and no contractions.** Write `you`, not `we` and not `the developer`.
Write `do not`, never `don't`. Full sentences with a subject and a verb.

**No emoji, anywhere.**

**No admonition syntax.** Not `> [!NOTE]`, not `:::warning`. Where you want a callout, write
a paragraph whose first phrase is bold, the way this list does.

**Banned shapes.** These are the ones an assistant produces by default:

- A `## Conclusion` that restates what was just said. End on the last real point, or on a
  `## Summary` that adds the shape of the argument rather than repeating it.
- `provides a robust and flexible way to`
- `This guide will walk you through`
- `By leveraging`
- `allows developers to`, `enables you to`, `makes it easy to`
- Negative parallelism: `not only X but also Y`, `X is not just Y, it is Z`
- Participial tails: `, ensuring the token is valid`, `, allowing you to rotate keys`
- `Let's dive in`, `deep dive`
- `It is worth noting that`. If it is, note it and skip the preamble.

**Word swaps.**

| Instead of | Write |
| --- | --- |
| `comprehensive` | full, or drop it |
| `robust` | reliable, or drop it |
| `seamless`, `seamlessly` | drop it |
| `leverage` | use |
| `utilize` | use |
| `crucial`, `vital` | important, or say what breaks without it |
| `powerful` | say what it actually does |
| `performant` | fast, or give the number |

Technical adjectives that carry information stay. `Constant-time comparison` is a fact
about how the code runs, and `zero-dependency` is a fact about `go.mod`.

**One concrete specific per claim.** A number, a default, a flag name, an error name, a
line of output. `Verification is fast` is worth nothing. `Verification costs 18 allocations
and about 2.5 microseconds on this machine` can be checked, and argued with.

**Concede a trade-off now and then.** Every design choice here cost something. Saying so is
what makes the rest of the page believable. `Enrich` verifying its input costs eight
allocations; the small-size brand cut drops a whole tooth; `Merge` splices raw JSON and can
therefore emit a duplicate key. Say it.

**Vary the rhythm.** Three sentences of the same length in a row is the sound of generated
text. Follow a long one with a short one.

## Editing rather than rewriting

Edit surgically. Text that already complies is left alone, and no edit changes the meaning
of a sentence to make it easier to phrase.

In a `.go` file you are editing comments only. Never touch code to fix prose. A doc comment
must still begin with the name of the thing it documents, which is a Go convention the
standard here does not override:

```go
// Verify checks a token's signature and its standard claims.
```

not

```go
// This function checks a token's signature.
```

Godoc has no emphasis syntax. `**bold**` in a doc comment renders as literal asterisks, and
`## Heading` renders as literal text, because a heading needs a space after a single `#`.
This package once carried over a thousand `**` markers that all rendered as punctuation.

## When the scanner is wrong

It will be, occasionally. A quoted error string containing a banned word, a rule name, a
literal example of the thing being warned against. Two ways out, in order of preference:

1. Put the text in backticks. Inline code is exempt, and a quoted error string usually
   should be code anyway.
2. Rephrase so the word is not needed.

Do not add an exemption to the scanner for one line. A rule with holes in it stops being a
rule people trust.
