# Building the book

The book is Markdown in this directory, rendered by a small Go program into one
self-contained HTML file, which a headless browser then prints to PDF.

```sh
cd book
go run .                  # HTML and PDF
go run . -format html     # HTML only, a couple of seconds, no browser
go run . -chapters 3      # the first three spine entries, for a fast loop
```

Both outputs land in `output/` and both are tracked. A repository where the book is a build
step nobody runs is a repository with no book.

## What you have to supply

| Requirement | Without it |
| --- | --- |
| Go 1.27 or newer | Nothing builds. |
| A Chromium-family browser on `PATH` or at a standard install location | No PDF. The HTML is still written, and the generator says so and exits zero. |
| `assets/paged.polyfill.js` | The book renders as one long scroll with no page numbers, no running headers and no page furniture in the PDF. |
| `assets/inter-roman-latin.woff2` and `assets/inter-italic-latin.woff2` | The text falls back to the reader's own sans-serif and every line break moves. |
| `../brand/jwt-mark-on-dark.svg` | The cover loses its mark. Rebuild it with `cd ../brand && go run .` |

Every one of those except Go is a warning rather than an error. A book that will not build
at all is worse than a book that builds slightly plainer, so the generator degrades and
tells you what it dropped.

The three files in `assets/` are vendored rather than fetched. `paged.polyfill.js` is
[Paged.js](https://pagedjs.org), under the MIT licence. The two `woff2` files are a Latin
subset of [Inter](https://rsms.me/inter/), under the SIL Open Font Licence. Both are
inlined into the output as data URIs, which is why the HTML is about three megabytes and
why it opens correctly from a USB stick in ten years.

## The spine

The reading order lives in `chapterFiles` in `main.go`, not in the directory listing. Adding
a Markdown file here does not add a chapter, and renaming one fails the build loudly rather
than dropping it silently.

`README.md` is the preface and carries no number. `epilogue.md` is back matter. Everything
between them is numbered by its position in the spine, so a gap in the filenames on disk
cannot produce a gap in the book.

## The chapter skeleton

`validate.go` refuses to build a chapter that breaks this, because the generator parses
parts of it literally and the rest fails quietly rather than loudly.

1. Exactly one H1, of the form `# Chapter N: Title`. The number is checked against the
   spine, which is how a book avoids ending up with two chapter sevens.
2. A lead paragraph.
3. The literal heading `## Table of Contents`, followed by a list of `[Text](#anchor)`
   links. **The anchors are checked.** Every `##` heading must be linked and every link must
   resolve, using GitHub's slug rules: lowercase, spaces to hyphens, everything that is not
   a letter, digit, hyphen or underscore removed. This block is stripped from the printed
   book, which has its own contents page; it is there for reading the file on GitHub.
4. Topical `##` sections. Never go deeper than `###`.
5. `## Summary`.
6. `## Further Reading`.
7. A `---` rule, then a next-chapter line: the words `Next Chapter` in bold, a colon, a
   markdown link whose text is the next chapter's title and whose target is its filename,
   then a hyphen and one clause. The link target is checked against the spine. Copy the
   footer from any existing chapter rather than retyping it. This footer is stripped from the printed book, because a
   "next chapter" link means nothing on paper.

The preface and the epilogue are continuous prose and carry none of items 3, 5, 6 or 7. A
preface with a Summary is repeating itself.

## Page size and code, which are one decision

The page is **A4 with 24mm, 20mm and 22mm margins**, giving about 170mm of text. That is not
a typography preference, it is a consequence of the code.

A 6 by 9 trim, which is the obvious choice for a technical book, leaves roughly 120mm of
measure. At 8.6pt that seats about 67 monospace characters. Go signatures do not fit in 67
characters: `VerifyEncryptedWithHeaderValidator` alone is 34, and the longest listing in
this book is 184 characters wide. A4 gives about 95, which seats all but a few.

**Code wraps. It does not scroll.** `overflow-x: auto` is meaningless on paper: there is no
scrollbar, so everything past the right edge is silently cut off and the reader cannot tell
a line was truncated. The first build of this book shipped with the right-hand half of
several listings missing, and it looked fine until somebody read a page.

So the print rules are:

```css
pre.code {
  white-space: pre-wrap;        /* wrap, keeping the indentation */
  overflow-wrap: break-word;    /* and break a token that has no wrap point, like a JWT */
  orphans: 4;                   /* never strand fewer than four lines across a page break */
  widows: 4;
  font-variant-ligatures: none; /* := and -> stay two characters */
  font-feature-settings: "liga" 0, "calt" 0, "dlig" 0;
}
```

Tables get `table-layout: fixed` and `overflow-wrap: break-word` for the same reason.

The screen half of the stylesheet does the opposite, under `@media screen`: a browser has a
scrollbar, so a long line keeps its shape there.

**If you change the page size, re-measure.** The relationship is: characters per line is
roughly the measure in millimetres divided by 1.8 at 8.6pt. Then rebuild and look at a page
with a long listing on it, because this is not a class of mistake that any check catches.

## Writing

The standard is `skill/human-writing/SKILL.md`, and it is checked:

```sh
pwsh ../skill/human-writing/scripts/scan-tells.ps1 03-claims.md
pwsh ../skill/human-writing/scripts/scan-tells.ps1 -Md      # the whole repository
```

Zero findings is the bar. The scanner is fence aware, so code samples are never reported.

**Verify every claim against the source.** Nothing here is compiled against the library it
describes, so nothing catches a wrong signature for you. `go doc -all .` from the repository
root prints every real signature in one place; use it rather than memory. This package's own
documentation once carried a dozen examples that could not compile, including a type that
does not exist.

## How the rendering works

- `main.go` holds the spine, the metadata type and the chapter loader.
- `validate.go` enforces the skeleton, before anything is rendered.
- `render.go` turns Markdown into HTML with `gomarkdown`, highlights code with `chroma`, and
  collects the `##` headings for the contents page. Heading ids are prefixed with the
  chapter's id, because the whole book is one document and an unprefixed `#summary` would
  resolve to whichever chapter came first.
- `template.go` inlines the stylesheet, the fonts, the polyfill and the brand mark, and
  holds the page template.
- `pdf.go` shells out to the browser.

The PDF step passes `--virtual-time-budget=60000`. The pagination polyfill rewrites the
whole document into pages after load, and on a book this size that takes a few seconds;
without the budget the browser prints whatever it has at the load event, which is an
unpaginated first screen. The budget is a ceiling rather than a delay, so the browser exits
as soon as the page goes quiet. A PDF under 64 KB is treated as a failed pagination and
reported, because that is what a blank page looks like.

## The cover

The cover mark is read from `../brand/jwt-mark-on-dark.svg` at build time rather than
copied here. One source of truth: change the mark in `brand/` and the cover follows. See
`brand/BRAND.md`.

There is no version anywhere in the book, on purpose. The library's version changes with
every release and the book does not, so a number on the cover would be wrong the week after
it was printed and nobody ever regenerates a PDF to fix one.

## Keeping the output current

`output/` is committed, so it can go stale the moment a chapter changes and nothing will
say so. The inputs are the chapters, `main.go`, `render.go`, `template.go`, `pdf.go`,
`styles.css`, `metadata.yml`, everything under `assets/`, and `../brand/jwt-mark-on-dark.svg`.
Touch any of them and rebuild before staging.

`go run . -format html` takes a couple of seconds and catches every structural error, so run
that while writing and keep the full build for the end.
