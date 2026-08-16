package main

import (
	"fmt"
	"strings"
)

// The palette. It is a sibling of the Iris kit rather than a copy: the gold is carried
// over unchanged, because that is the family tie, and the blue moves from Iris indigo to
// Aegean so the two marks are never mistaken for each other.
const (
	Aegean = "#0D5EAF" // primary, on light grounds
	Deep   = "#08406F" // depth
	Sky    = "#4E9BE0" // primary, on dark grounds
	Gold   = "#F5C542" // the bit of the key, the hole, the signature. Shared with Iris.
	Marble = "#F4F1EA" // warm off-white ground
	Field  = "#0A0E1F" // dark ground. Shared with Iris.
)

// Ground says which field the art will sit on. The blue lifts one stop on dark, because
// Aegean sinks into #0A0E1F.
type Ground int

const (
	Light Ground = iota
	Dark
)

func (g Ground) blue() string {
	if g == Dark {
		return Sky
	}
	return Aegean
}

// The mark: a key whose three teeth are the three dot-separated segments of a JWT, and
// whose bit is gold because the third segment is the signature.
//
// Inline safety, and these are not preferences. Flat colour only, no gradients, no
// filters, no <defs>, no ids, no <style>, no CSS classes, no var(). Presentation
// attributes with hardcoded hex, nothing else. Ids collide when several of these land in
// one document, and Chrome rasterizes a filtered subtree when printing to PDF, which
// silently turns the vector into a bitmap in the book.
//
// body returns the inner markup of a 24 by 24 viewBox.
func markBody(blue string) string {
	return fmt.Sprintf(`
  <circle cx="8" cy="10.4" r="5.2" stroke="%[1]s" stroke-width="2.9" fill="none"/>
  <circle cx="8" cy="10.4" r="1.7" fill="%[2]s"/>
  <path d="M13.2 10.4H21" stroke="%[1]s" stroke-width="2.9" stroke-linecap="round"/>
  <path d="M14.9 11.7V18.6" stroke="%[1]s" stroke-width="2.6" stroke-linecap="round"/>
  <path d="M17.9 11.7V16.2" stroke="%[1]s" stroke-width="2.6" stroke-linecap="round"/>
  <path d="M20.9 11.7V18.6" stroke="%[2]s" stroke-width="2.6" stroke-linecap="round"/>`,
		blue, Gold)
}

// The small-size cut, for 32 pixels and below.
//
// It is not the mark scaled down. Below about 48 pixels the gap between the three teeth
// goes sub-pixel and they merge into one grey wedge, and the ring's hole closes up. So:
// two teeth instead of three, every stroke heavier, the ring larger and its hole wider,
// and the whole key sitting slightly lower to use the box.
//
// The teeth are the first and the last, so the gold one survives. It is the only colour in
// the mark besides the blue, and losing it would leave a monochrome blob.
//
// The ring is the part that decides whether this works. Its stroke is thinner here than
// you would expect from a "heavier" cut, and its radius larger, because what has to be
// protected is the gap between the hole and the ring: at 16 pixels that gap was down to
// about one pixel and closed into a grey smear, taking the whole ring with it. Widening
// the gap matters more than thickening the stroke.
func markSmallBody(blue string) string {
	return fmt.Sprintf(`
  <circle cx="8" cy="10.2" r="5.7" stroke="%[1]s" stroke-width="3.4" fill="none"/>
  <circle cx="8" cy="10.2" r="1.6" fill="%[2]s"/>
  <path d="M13.7 10.2H20.9" stroke="%[1]s" stroke-width="3.4" stroke-linecap="round"/>
  <path d="M15.2 11.8V18.8" stroke="%[1]s" stroke-width="3.2" stroke-linecap="round"/>
  <path d="M20.7 11.8V18.8" stroke="%[2]s" stroke-width="3.2" stroke-linecap="round"/>`,
		blue, Gold)
}

// The monochrome cut inherits currentColor, for a single-ink context: a stamp, an
// embroidered patch, a terminal that only has one colour to give.
func markMonoBody() string {
	return `
  <circle cx="8" cy="10.4" r="5.2" stroke="currentColor" stroke-width="2.9" fill="none"/>
  <circle cx="8" cy="10.4" r="1.7" fill="currentColor"/>
  <path d="M13.2 10.4H21" stroke="currentColor" stroke-width="2.9" stroke-linecap="round"/>
  <path d="M14.9 11.7V18.6" stroke="currentColor" stroke-width="2.6" stroke-linecap="round"/>
  <path d="M17.9 11.7V16.2" stroke="currentColor" stroke-width="2.6" stroke-linecap="round"/>
  <path d="M20.9 11.7V18.6" stroke="currentColor" stroke-width="2.6" stroke-linecap="round"/>`
}

// The wordmark is drawn, not set.
//
// Outlined rather than live text so the lockup renders the same everywhere, with no font
// to load and nothing to fall back to. It is built from the same round-capped strokes as
// the key, at the same weight, which is what makes the two read as one object rather than
// a logo with a caption.
//
// Drawn on a 0 0 58 24 grid with the baseline at y=19.
func wordmarkBody(ink string) string {
	return fmt.Sprintf(`
  <g stroke="%[1]s" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" fill="none">
    <path d="M8.6 8.2V17.4C8.6 19.6 7 20.8 4.8 20.4"/>
    <path d="M15.4 8.4L18.6 17.6L22.2 11.4L25.8 17.6L29 8.4"/>
    <path d="M39.2 3.6V15.4C39.2 17.2 40.2 18.1 42 17.9"/>
    <path d="M34.6 9.2H43.4"/>
  </g>
  <circle cx="8.6" cy="3.6" r="1.9" fill="%[1]s"/>`, ink)
}

// svgDoc wraps inner markup in a document. role and title give assistive technology
// something to say; aria-hidden is used instead where the art is decorative.
func svgDoc(viewBox, title, inner string) string {
	var b strings.Builder
	b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="`)
	b.WriteString(viewBox)
	b.WriteString(`" fill="none" role="img" aria-label="`)
	b.WriteString(title)
	b.WriteString(`">`)
	b.WriteString(inner)
	b.WriteString("\n</svg>\n")
	return b.String()
}

const header = `<!-- Generated by brand/main.go. Do not edit by hand: run "cd brand && go run ." instead.
     Flat colour only, no gradients, no defs, no ids, no style block, no CSS classes and
     no filters, so this is safe to inline anywhere, including into a document that
     already holds several of them. See brand/BRAND.md. -->
`

func markSVG(g Ground) string {
	return header + svgDoc("0 0 24 24", "jwt", markBody(g.blue()))
}

func markSmallSVG(g Ground) string {
	return header + svgDoc("0 0 24 24", "jwt", markSmallBody(g.blue()))
}

func markMonoSVG() string {
	return header + svgDoc("0 0 24 24", "jwt", markMonoBody())
}

// The lockup: the mark, a gap of one mark-width, then the wordmark.
func lockupSVG(g Ground) string {
	ink := Aegean
	if g == Dark {
		ink = Marble
	}

	inner := fmt.Sprintf(`
  <g transform="translate(0 2)">%s
  </g>
  <g transform="translate(32 2)">%s
  </g>`, markBody(g.blue()), wordmarkBody(ink))

	return header + svgDoc("0 0 92 28", "jwt", inner)
}

// The hero embeds the same mark constant, scaled into a scene, so the two cannot drift.
// Sized 2:1, which is what a social card wants and what sits well above a README.
//
// The block is centred on the canvas rather than set from a left margin. The first version
// started everything at x=408 and left a third of the card empty on the right, which is
// obvious the moment you look at the render and invisible while you are reading the
// numbers.
func heroSVG() string {
	inner := fmt.Sprintf(`
  <rect width="1280" height="640" fill="%[1]s"/>
  <g transform="translate(497 106) scale(12)">%[2]s
  </g>
  <g transform="translate(565 372) scale(3.1)">%[3]s
  </g>
  <path d="M555 470H725" stroke="%[4]s" stroke-width="3" stroke-linecap="round" opacity="0.45"/>`,
		Field, markBody(Sky), wordmarkBody(Marble), Gold)

	return header + svgDoc("0 0 1280 640", "jwt", inner)
}
