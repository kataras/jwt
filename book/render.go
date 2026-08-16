package main

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"os"
	"strings"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/ast"
	"github.com/gomarkdown/markdown/html"
	"github.com/gomarkdown/markdown/parser"
	"gopkg.in/yaml.v3"
)

func loadMetadata(filename string) (Metadata, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return Metadata{}, err
	}

	var meta Metadata
	if err = yaml.Unmarshal(b, &meta); err != nil {
		return Metadata{}, fmt.Errorf("%s: %w", filename, err)
	}

	if meta.Title == "" {
		return Metadata{}, fmt.Errorf("%s: title is empty", filename)
	}

	return meta, nil
}

// render turns one markdown file into HTML and collects its headings.
func (ch *Chapter) render(source []byte) error {
	source = reNextFooter.ReplaceAll(source, nil)
	source = stripChapterTOC(source)

	m := reH1.FindSubmatch(source)
	if m == nil {
		return fmt.Errorf("no H1 heading found; every chapter needs exactly one")
	}

	title, err := cleanTitle(string(bytes.TrimSpace(m[1])), ch.Number)
	if err != nil {
		return err
	}

	ch.Title = title
	ch.ID = "ch-" + slug(ch.File)

	// The H1 is dropped from the body: the chapter opener prints it, and printing it
	// twice is the sort of thing nobody notices until the PDF is out.
	source = reH1.ReplaceAll(source, nil)

	p := parser.NewWithExtensions(parser.CommonExtensions | parser.AutoHeadingIDs | parser.Footnotes)
	doc := p.Parse(source)

	ch.collectSections(doc)

	renderer := html.NewRenderer(html.RendererOptions{
		Flags:          html.CommonFlags,
		RenderNodeHook: ch.renderNode,
	})

	ch.Body = template.HTML(markdown.Render(doc, renderer))
	return nil
}

// collectSections walks the tree for H2 headings, which become the chapter's entry in the
// contents page. Nothing deeper is collected: a contents page listing every H3 is a wall.
func (ch *Chapter) collectSections(doc ast.Node) {
	ast.WalkFunc(doc, func(node ast.Node, entering bool) ast.WalkStatus {
		heading, ok := node.(*ast.Heading)
		if !ok || !entering || heading.Level != 2 {
			return ast.GoToNext
		}

		title := nodeText(heading)
		switch title {
		case "Summary", "Further Reading":
			// Present in every chapter by design, so listing them says nothing.
			return ast.GoToNext
		}

		ch.Sections = append(ch.Sections, Section{
			ID:    ch.ID + "-" + heading.HeadingID,
			Title: title,
		})

		return ast.GoToNext
	})
}

// renderNode handles the two node types this book renders differently from the default.
//
// The writer is not really an io.Writer that can fail. markdown.Render allocates a
// bytes.Buffer, hands the same one to every hook, and returns its bytes; the interface is
// only there because the renderer's signature is fixed. bytes.Buffer.Write is documented
// to always return a nil error and to panic rather than report one when it runs out of
// memory, so the writes here and in renderCodeBlock and highlight discard their results
// explicitly rather than threading an error that can never arrive through three functions.
func (ch *Chapter) renderNode(w io.Writer, node ast.Node, entering bool) (ast.WalkStatus, bool) {
	switch n := node.(type) {
	case *ast.CodeBlock:
		return ch.renderCodeBlock(w, n)
	case *ast.Heading:
		// Prefix every heading id with the chapter's, because the whole book is one
		// document and "#summary" would otherwise resolve to whichever chapter came
		// first. This is the bug that makes every "Summary" link in a single-file book
		// land in chapter one.
		if entering && n.HeadingID != "" {
			_, _ = fmt.Fprintf(w, `<h%d id="%s-%s">`, n.Level, ch.ID, n.HeadingID)
		} else if !entering {
			_, _ = fmt.Fprintf(w, "</h%d>\n", n.Level)
		}
		return ast.GoToNext, true
	}

	return ast.GoToNext, false
}

func (ch *Chapter) renderCodeBlock(w io.Writer, cb *ast.CodeBlock) (ast.WalkStatus, bool) {
	lang := strings.ToLower(strings.TrimSpace(string(cb.Info)))
	if i := strings.IndexAny(lang, " \t"); i > 0 {
		lang = lang[:i]
	}

	_, _ = fmt.Fprintf(w, `<pre class="code lang-%s"><code>`, template.HTMLEscapeString(lang))
	if err := highlight(w, lang, string(cb.Literal)); err != nil {
		template.HTMLEscape(w, cb.Literal)
	}
	_, _ = io.WriteString(w, "</code></pre>\n")

	return ast.GoToNext, true
}

// highlight writes syntax-highlighted HTML for a code block.
//
// The tokens carry class names rather than inline styles, and the stylesheet defines the
// colours, so the same markup works on the screen and on paper without a second pass.
func highlight(w io.Writer, lang, code string) error {
	lexer := lexers.Get(lang)
	if lexer == nil {
		return fmt.Errorf("no lexer for %q", lang)
	}
	lexer = chroma.Coalesce(lexer)

	iterator, err := lexer.Tokenise(nil, code)
	if err != nil {
		return err
	}

	for _, token := range iterator.Tokens() {
		class := tokenClass(token.Type)
		if class == "" {
			template.HTMLEscape(w, []byte(token.Value))
			continue
		}

		_, _ = fmt.Fprintf(w, `<span class="%s">`, class)
		template.HTMLEscape(w, []byte(token.Value))
		_, _ = io.WriteString(w, "</span>")
	}

	return nil
}

// tokenClass maps a chroma token to one of a handful of classes.
//
// Chroma has dozens of token types and this book uses six. Collapsing them here keeps the
// stylesheet short and the printed page calm: a listing with eleven colours in it is
// harder to read than one with four, whatever the screenshot suggests.
func tokenClass(tt chroma.TokenType) string {
	switch tt.Category() {
	case chroma.Comment:
		return "c"
	case chroma.Keyword:
		return "k"
	case chroma.Literal:
		switch tt.SubCategory() {
		case chroma.LiteralString:
			return "s"
		case chroma.LiteralNumber:
			return "n"
		}
		return ""
	case chroma.Name:
		switch tt {
		case chroma.NameFunction, chroma.NameClass, chroma.NameBuiltin:
			return "f"
		case chroma.NameAttribute, chroma.NameTag:
			return "a"
		}
		return ""
	default:
		return ""
	}
}

func nodeText(node ast.Node) string {
	var b strings.Builder
	ast.WalkFunc(node, func(n ast.Node, entering bool) ast.WalkStatus {
		if entering {
			if leaf := n.AsLeaf(); leaf != nil {
				b.Write(leaf.Literal)
			}
		}
		return ast.GoToNext
	})
	return strings.TrimSpace(b.String())
}

// slug turns a filename into an id fragment.
func slug(file string) string {
	s := strings.TrimSuffix(file, ".md")
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "_", "-")
	return s
}
