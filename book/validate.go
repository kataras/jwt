package main

import (
	"fmt"
	"regexp"
	"strings"
)

// The chapter skeleton is not a style guide, it is a contract. The generator parses parts
// of it literally: the H1 gives the chapter its title and checks its number, the "Table of
// Contents" block is stripped because the book has its own contents page, and the
// "Next Chapter" footer is stripped because it means nothing on paper.
//
// A chapter that does not follow it does not fail loudly at render time. It fails quietly:
// a missing Summary is a chapter that stops mid-thought, and a table of contents whose
// anchors do not resolve is a set of links that silently go nowhere in the HTML. So the
// build checks, and refuses.
//
// Every message here names the file and says what to do about it.

var (
	reHeading2   = regexp.MustCompile(`(?m)^## +(.+?)\s*$`)
	reHeading4   = regexp.MustCompile(`(?m)^#{4,} `)
	reTOCLink    = regexp.MustCompile(`\[[^\]]*\]\(#([^)]+)\)`)
	reFooterLink = regexp.MustCompile(`(?m)^\*\*Next Chapter\*\*: \[[^\]]+\]\(([^)]+)\)`)
	reFence      = regexp.MustCompile("(?s)```.*?```")
)

// validate checks one chapter's source against the skeleton.
//
// It runs on the raw file, before anything is stripped, because the parts it checks are
// exactly the parts the renderer removes.
func validate(file string, source []byte, number int, nextFile string) error {
	text := string(source)

	// Fenced code can contain anything, including lines that look like headings.
	text = reFence.ReplaceAllString(text, "")

	var problems []string

	// One H1, in the right form. cleanTitle checks the number; this checks the count.
	h1s := reH1.FindAllString(text, -1)
	switch {
	case len(h1s) == 0:
		problems = append(problems, "no H1. Every unit needs exactly one")
	case len(h1s) > 1:
		problems = append(problems, fmt.Sprintf("%d H1 headings, expected exactly one: %s",
			len(h1s), strings.Join(h1s, " / ")))
	}

	headings := reHeading2.FindAllStringSubmatch(text, -1)
	names := make([]string, 0, len(headings))
	for _, h := range headings {
		names = append(names, strings.TrimSpace(h[1]))
	}

	// Front and back matter are continuous prose. A preface with a Summary is repeating
	// itself, and an epilogue with Further Reading is a chapter pretending to be an
	// ending. Only the numbered chapters carry the full skeleton.
	if number > 0 {
		for _, required := range []string{"Table of Contents", "Summary", "Further Reading"} {
			if !contains(names, required) {
				problems = append(problems, fmt.Sprintf("no \"## %s\" section", required))
			}
		}

		if contains(names, "Table of Contents") {
			problems = append(problems, checkTOCAnchors(text, names)...)
		}
	}

	if reHeading4.MatchString(text) {
		problems = append(problems, "a heading deeper than ###. Three levels is the limit")
	}

	// The footer, and that it points where the spine says it should.
	if nextFile != "" {
		m := reFooterLink.FindStringSubmatch(text)
		switch {
		case m == nil:
			problems = append(problems, fmt.Sprintf(
				"no footer. End with a --- rule and **Next Chapter**: [Title](%s)", nextFile))
		case m[1] != nextFile:
			problems = append(problems, fmt.Sprintf(
				"the footer points at %q but the spine says the next unit is %q", m[1], nextFile))
		}
	}

	if len(problems) == 0 {
		return nil
	}

	return fmt.Errorf("%s does not follow the chapter skeleton:\n  - %s",
		file, strings.Join(problems, "\n  - "))
}

// checkTOCAnchors compares the links in the contents block against the headings that
// follow it.
//
// A link to "#the-signature" when the heading is "What the signature covers" is a dead
// link in the rendered book, and nothing else notices: the anchor simply does not resolve
// and the reader lands at the top of the page.
func checkTOCAnchors(text string, headings []string) []string {
	start := strings.Index(text, "## Table of Contents")
	if start < 0 {
		return nil
	}

	rest := text[start+len("## Table of Contents"):]
	if next := strings.Index(rest, "\n## "); next >= 0 {
		rest = rest[:next]
	}

	real := make(map[string]bool, len(headings))
	for _, h := range headings {
		if h == "Table of Contents" {
			continue
		}
		real[githubSlug(h)] = true
	}

	var problems []string
	linked := make(map[string]bool)

	for _, m := range reTOCLink.FindAllStringSubmatch(rest, -1) {
		anchor := m[1]
		linked[anchor] = true
		if !real[anchor] {
			problems = append(problems, fmt.Sprintf(
				"the contents link #%s matches no heading in this chapter", anchor))
		}
	}

	for _, h := range headings {
		if h == "Table of Contents" {
			continue
		}
		if !linked[githubSlug(h)] {
			problems = append(problems, fmt.Sprintf(
				"the heading %q is missing from the contents block", h))
		}
	}

	return problems
}

// githubSlug reproduces the anchor GitHub generates for a heading: lowercase, spaces to
// hyphens, and everything that is not a letter, a digit, a hyphen or an underscore
// removed.
func githubSlug(heading string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(heading) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('-')
		}
	}
	return b.String()
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
