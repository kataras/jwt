package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
)

// assets holds everything inlined into the single output file.
//
// Each one is optional. A missing asset degrades the book rather than failing it, and says
// so on the way past, because a book that will not build is worse than a plainer book.
type assets struct {
	Styles     template.CSS
	Paged      template.JS
	FontRoman  template.URL
	FontItalic template.URL
	Mark       template.HTML

	missing []string
}

func (a assets) warn() {
	for _, m := range a.missing {
		fmt.Println("book:", m)
	}
}

func loadAssets() (assets, error) {
	var a assets

	css, err := os.ReadFile("styles.css")
	if err != nil {
		return a, fmt.Errorf("styles.css is required: %w", err)
	}
	a.Styles = template.CSS(css)

	if js, err := os.ReadFile(filepath.Join("assets", "paged.polyfill.js")); err == nil {
		a.Paged = template.JS(js)
	} else {
		a.missing = append(a.missing,
			"assets/paged.polyfill.js is missing, so the book renders as one long scroll "+
				"with no page numbers and no running headers. See README_EBOOK.md.")
	}

	for _, f := range []struct {
		file string
		dst  *template.URL
		name string
	}{
		{"inter-roman-latin.woff2", &a.FontRoman, "roman"},
		{"inter-italic-latin.woff2", &a.FontItalic, "italic"},
	} {
		uri, err := dataURI(filepath.Join("assets", f.file), "font/woff2")
		if err != nil {
			a.missing = append(a.missing, fmt.Sprintf(
				"assets/%s is missing, so the %s text falls back to the reader's own sans-serif "+
					"and every line break moves. See README_EBOOK.md.", f.file, f.name))
			continue
		}
		*f.dst = uri
	}

	// The cover mark comes from the brand module's generated SVG, not from a copy kept
	// here. One source of truth: change the mark in brand/ and the cover follows.
	if mark, err := readBrandSVG("jwt-mark-on-dark.svg"); err == nil {
		a.Mark = template.HTML(mark)
	} else {
		a.missing = append(a.missing,
			"../brand/jwt-mark-on-dark.svg is missing, so the cover has no mark. "+
				"Run: cd ../brand && go run .")
	}

	return a, nil
}

func dataURI(path, mime string) (template.URL, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	return template.URL("data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(b)), nil
}

// readBrandSVG reads a generated brand file and returns its <svg> element.
//
// The generator writes an XML comment above the element; that comment is stripped here so
// the markup can be dropped straight into the page.
func readBrandSVG(name string) (string, error) {
	b, err := os.ReadFile(filepath.Join("..", "brand", name))
	if err != nil {
		return "", err
	}

	i := bytes.Index(b, []byte("<svg"))
	if i < 0 {
		return "", fmt.Errorf("%s does not contain an <svg> element", name)
	}

	return string(b[i:]), nil
}

type bookData struct {
	Meta     Metadata
	Chapters []*Chapter
	Assets   assets
	Host     string
}

func renderBook(meta Metadata, chapters []*Chapter) ([]byte, error) {
	a, err := loadAssets()
	if err != nil {
		return nil, err
	}
	a.warn()

	t, err := template.New("book").Parse(bookTemplate)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	err = t.Execute(&buf, bookData{
		Meta:     meta,
		Chapters: chapters,
		Assets:   a,
		Host:     host(meta.Website),
	})
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func host(website string) string {
	s := strings.TrimPrefix(website, "https://")
	s = strings.TrimPrefix(s, "http://")
	return strings.TrimSuffix(s, "/")
}

const bookTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Meta.Title}} &mdash; {{.Meta.Subtitle}}</title>
<meta name="author" content="{{.Meta.Author}}">
<meta name="description" content="{{.Meta.Description}}">
<style>
{{- if .Assets.FontRoman}}
@font-face {
  font-family: "Inter Book";
  font-style: normal;
  font-weight: 100 900;
  font-display: block;
  src: url("{{.Assets.FontRoman}}") format("woff2");
}
{{- end}}
{{- if .Assets.FontItalic}}
@font-face {
  font-family: "Inter Book";
  font-style: italic;
  font-weight: 100 900;
  font-display: block;
  src: url("{{.Assets.FontItalic}}") format("woff2");
}
{{- end}}
{{.Assets.Styles}}
</style>
</head>
<body>

<section class="cover">
  <div class="cover-mark">{{.Assets.Mark}}</div>
  <h1 class="cover-title">{{.Meta.Title}}</h1>
  <p class="cover-subtitle">{{.Meta.Subtitle}}</p>
  <div class="cover-rule"></div>
  <p class="cover-author">{{.Meta.Author}}</p>
  {{- if .Meta.Credit}}
  <ul class="cover-credit">
    {{- range .Meta.Credit}}
    <li>{{.}}</li>
    {{- end}}
  </ul>
  {{- end}}
  <p class="cover-edition">{{.Meta.Edition}}</p>
</section>

<section class="frontmatter">
  <h1>Contents</h1>
  <ol class="toc">
    {{- range .Chapters}}
    <li class="toc-chapter{{if eq .Number 0}} toc-unnumbered{{end}}">
      <a href="#{{.ID}}">
        {{- if gt .Number 0}}<span class="toc-num">{{.Number}}</span>{{end}}
        <span class="toc-title">{{.Title}}</span>
      </a>
      {{- if .Sections}}
      <ul class="toc-sections">
        {{- range .Sections}}
        <li><a href="#{{.ID}}">{{.Title}}</a></li>
        {{- end}}
      </ul>
      {{- end}}
    </li>
    {{- end}}
  </ol>
</section>

{{range .Chapters}}
<section class="chapter" id="{{.ID}}">
  <header class="chapter-head">
    {{- if gt .Number 0}}
    <p class="chapter-eyebrow">Chapter {{.Number}}</p>
    {{- end}}
    <h1 class="chapter-title">{{.Title}}</h1>
  </header>
  {{.Body}}
</section>
{{end}}

<section class="colophon">
  <h1>Colophon</h1>
  <p>{{.Meta.Description}}</p>
  <dl>
    <dt>Repository</dt><dd>{{.Meta.Repository}}</dd>
    {{- if .Meta.Website}}
    <dt>Website</dt><dd>{{.Host}}</dd>
    {{- end}}
    <dt>Licence</dt><dd>{{.Meta.License}}</dd>
  </dl>
  <p class="colophon-note">Set in Inter. Rendered from Markdown to a single HTML file, then
  printed to PDF through a headless browser. The whole book is one file with nothing
  external in it: no fonts to fetch, no scripts to load, no images to go missing.</p>
</section>

{{- if .Assets.Paged}}
<script>{{.Assets.Paged}}</script>
{{- end}}
</body>
</html>
`
