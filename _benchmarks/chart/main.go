// Command chart turns `go test -bench` output into the SVG charts the READMEs embed.
//
// The charts are self-contained SVG documents rendered without a chart library, so the
// output is deterministic, adds no dependency to this module, and works wherever an <img>
// works, GitHub READMEs included. Values are printed at every bar tip, because a static
// image has no tooltips, and a prefers-color-scheme block adapts the chart to light and
// dark pages.
//
// The approach is the one used in github.com/kataras/server-benchmarks. The colour for
// kataras/jwt is Aegean from brand/BRAND.md, so the chart and the mark agree.
//
// Usage:
//
//	cd _benchmarks && go run ./chart            # run the benchmarks, then draw
//	cd _benchmarks && go run ./chart -in b.txt  # draw from a saved run
//	cd _benchmarks && go run ./chart -benchtime 3s
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func main() {
	var (
		in        = flag.String("in", "", "read `go test -bench` output from this file instead of running the benchmarks")
		out       = flag.String("out", ".", "directory to write the SVG files into")
		benchtime = flag.String("benchtime", "", "value for the -benchtime flag, e.g. 3s")
		note      = flag.String("note", "", "extra provenance for the chart footer, e.g. the CPU model")
	)
	flag.Parse()

	raw, err := load(*in, *benchtime)
	if err != nil {
		fmt.Fprintf(os.Stderr, "chart: %v\n", err)
		os.Exit(1)
	}

	run, err := parse(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "chart: %v\n", err)
		os.Exit(1)
	}

	for _, m := range metrics {
		groups := run.groups(m)
		if len(groups) == 0 {
			continue
		}

		svg := render(m, groups, run.platform(*note))
		path := filepath.Join(*out, m.file)
		if err := os.WriteFile(path, svg, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "chart: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("wrote %s (%d results across %d groups)\n", path, run.count(), len(groups))
	}
}

// load returns the benchmark output, either from a file or by running the benchmarks.
func load(in, benchtime string) (string, error) {
	if in != "" {
		b, err := os.ReadFile(in)
		return string(b), err
	}

	args := []string{"test", "-bench=.", "-benchmem", "-run=XXX"}
	if benchtime != "" {
		args = append(args, "-benchtime", benchtime)
	}

	fmt.Fprintln(os.Stderr, "chart: running the benchmarks, this takes a minute...")
	cmd := exec.Command("go", args...)
	cmd.Stderr = os.Stderr
	b, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("go %s: %w", strings.Join(args, " "), err)
	}

	return string(b), nil
}

// result is one benchmark line.
type result struct {
	op      string // "Sign a token", "Verify a token"
	library string // "kataras/jwt", "golang-jwt", "go-jose"
	variant string // "map", "struct", "" when there is only one
	slot    int    // colour slot of the library

	nsPerOp    float64
	bytesPerOp float64
	allocsPeri float64
}

// name is the row label: the library, plus the variant when a library has more than one.
func (r result) name() string {
	if r.variant == "" {
		return r.library
	}

	return r.library + " (" + r.variant + ")"
}

// benchRun is a parsed `go test -bench` run.
type benchRun struct {
	results []result
	goos    string
	goarch  string
	cpu     string
}

func (b benchRun) count() int { return len(b.results) }

// platform is the one-line provenance printed under the chart. A benchmark chart without
// the machine it was measured on invites comparison against numbers from another machine.
//
// note is appended when given. It exists because `go test` prints a cpu: line on amd64 and
// not on arm64, so on some machines the model has to be supplied from outside.
func (b benchRun) platform(note string) string {
	parts := make([]string, 0, 3)
	if b.goos != "" && b.goarch != "" {
		parts = append(parts, b.goos+"/"+b.goarch)
	}
	if b.cpu != "" {
		parts = append(parts, b.cpu)
	}
	if note != "" {
		parts = append(parts, note)
	}

	return strings.Join(parts, "  ·  ")
}

var (
	// e.g. "BenchmarkSign_Map-12   498718   2447 ns/op   1528 B/op   23 allocs/op"
	benchLine = regexp.MustCompile(
		`^Benchmark(\S+?)(?:-\d+)?\s+\d+\s+([\d.]+)\s+ns/op\s+([\d.]+)\s+B/op\s+([\d.]+)\s+allocs/op`)
	headerLine = regexp.MustCompile(`^(goos|goarch|cpu):\s*(.*)$`)
)

// parse reads the benchmark output into results.
func parse(raw string) (benchRun, error) {
	var run benchRun

	sc := bufio.NewScanner(strings.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")

		if m := headerLine.FindStringSubmatch(line); m != nil {
			switch m[1] {
			case "goos":
				run.goos = m[2]
			case "goarch":
				run.goarch = m[2]
			case "cpu":
				run.cpu = m[2]
			}
			continue
		}

		m := benchLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		ns, err := strconv.ParseFloat(m[2], 64)
		if err != nil {
			return run, fmt.Errorf("ns/op in %q: %w", line, err)
		}
		bytes, err := strconv.ParseFloat(m[3], 64)
		if err != nil {
			return run, fmt.Errorf("B/op in %q: %w", line, err)
		}
		allocs, err := strconv.ParseFloat(m[4], 64)
		if err != nil {
			return run, fmt.Errorf("allocs/op in %q: %w", line, err)
		}

		r := classify(m[1])
		r.nsPerOp, r.bytesPerOp, r.allocsPeri = ns, bytes, allocs
		run.results = append(run.results, r)
	}
	if err := sc.Err(); err != nil {
		return run, err
	}

	if len(run.results) == 0 {
		return run, fmt.Errorf("no benchmark results found: was the output from `go test -bench=. -benchmem`?")
	}

	return run, nil
}

// classify turns a benchmark function name into the operation, library and variant it
// measures. The names encode the library in the middle: Sign_jwt_go_Map is golang-jwt
// signing a map, Verify_go_jose is go-jose verifying. Anything without a library marker is
// this package, which is why the check is for the competitors and the default is jwt.
func classify(name string) result {
	r := result{op: "Sign a token"}
	if strings.HasPrefix(name, "Verify") {
		r.op = "Verify a token"
	}

	rest := name
	for _, prefix := range []string{"Sign_", "Sign", "Verify_", "Verify"} {
		if strings.HasPrefix(rest, prefix) {
			rest = strings.TrimPrefix(rest, prefix)
			break
		}
	}

	switch {
	case strings.HasPrefix(rest, "jwt_go"):
		r.library, r.slot = "golang-jwt", 1
		rest = strings.TrimPrefix(rest, "jwt_go")
	case strings.HasPrefix(rest, "go_jose"):
		r.library, r.slot = "go-jose", 2
		rest = strings.TrimPrefix(rest, "go_jose")
	default:
		r.library, r.slot = "kataras/jwt", 0
	}

	r.variant = strings.ToLower(strings.ReplaceAll(strings.Trim(rest, "_"), "_", " "))
	if r.variant == "struct2" {
		r.variant = "struct 2"
	}

	return r
}

// metric is one chart: which field it reads and how it labels a bar.
type metric struct {
	file     string
	title    string
	subtitle string
	value    func(result) float64
	label    func(result) string
}

var metrics = []metric{
	{
		file:     "benchmarks.svg",
		title:    "Time per operation",
		subtitle: "nanoseconds, lower is better",
		value:    func(r result) float64 { return r.nsPerOp },
		label: func(r result) string {
			return thousands(r.nsPerOp) + " ns"
		},
	},
	{
		file:     "benchmarks-allocations.svg",
		title:    "Allocations per operation",
		subtitle: "count, lower is better",
		value:    func(r result) float64 { return r.allocsPeri },
		label: func(r result) string {
			return thousands(r.allocsPeri) + " allocs"
		},
	},
	{
		file:     "benchmarks-memory.svg",
		title:    "Memory per operation",
		subtitle: "bytes, lower is better",
		value:    func(r result) float64 { return r.bytesPerOp },
		label: func(r result) string {
			return thousands(r.bytesPerOp) + " B"
		},
	},
}

// group is one titled block of bars.
type group struct {
	title string
	bars  []bar
}

// bar is one row.
type bar struct {
	name  string
	slot  int
	value float64
	label string
}

// groups buckets the results by operation and ranks each bucket best first. Sign and
// Verify are separate blocks rather than one ranking, because ranking them together would
// invite reading a Verify bar against a Sign bar, which measures nothing.
func (b benchRun) groups(m metric) []group {
	order := []string{"Sign a token", "Verify a token"}
	byOp := make(map[string][]result)
	for _, r := range b.results {
		byOp[r.op] = append(byOp[r.op], r)
	}

	groups := make([]group, 0, len(order))
	for _, op := range order {
		rs := byOp[op]
		if len(rs) == 0 {
			continue
		}

		sort.SliceStable(rs, func(i, j int) bool {
			if m.value(rs[i]) != m.value(rs[j]) {
				return m.value(rs[i]) < m.value(rs[j])
			}
			return rs[i].name() < rs[j].name()
		})

		bars := make([]bar, 0, len(rs))
		for _, r := range rs {
			bars = append(bars, bar{name: r.name(), slot: r.slot, value: m.value(r), label: m.label(r)})
		}
		groups = append(groups, group{title: op, bars: bars})
	}

	return groups
}

// Chart geometry, in pixels.
const (
	chartWidth    = 900
	chartPadX     = 20
	chartHeaderH  = 74 // title, subtitle and legend.
	chartGroupH   = 26 // a group's own heading.
	chartRowH     = 28
	chartBarH     = 16
	chartGroupGap = 10
	chartFooterH  = 30
	chartNameW    = 200 // right-aligned name column.
	chartValueW   = 120 // reserved for the value label at the bar tip.
)

const chartFont = "system-ui, -apple-system, 'Segoe UI', sans-serif"

// chartStyle is the light palette with a dark override. Slot 0 is Aegean from
// brand/BRAND.md, so this library's bars carry the project's own colour; slots 1 and 2 are
// picked to stay distinguishable from it and from each other on both surfaces, including
// for the common colour-vision deficiencies.
const chartStyle = `text{font-family:` + chartFont + `}
.surface{fill:#fcfcfb;stroke:rgba(11,11,11,0.10)}
.title{fill:#0b0b0b;font-size:15px;font-weight:600}
.subtitle{fill:#898781;font-size:12px}
.group{fill:#0b0b0b;font-size:12px;font-weight:600;letter-spacing:0.04em}
.name{fill:#0b0b0b;font-size:12.5px}
.value{fill:#52514e;font-size:12px}
.legend{fill:#52514e;font-size:11.5px}
.footer{fill:#898781;font-size:11px}
.baseline{stroke:#c3c2b7;stroke-width:1}
.s0{fill:#0D5EAF}.s1{fill:#EB6834}.s2{fill:#1BAF7A}
@media (prefers-color-scheme: dark){
.surface{fill:#1a1a19;stroke:rgba(255,255,255,0.10)}
.title{fill:#ffffff}
.group{fill:#ffffff}
.name{fill:#ffffff}
.value{fill:#c3c2b7}
.legend{fill:#c3c2b7}
.footer{fill:#898781}
.baseline{stroke:#383835}
.s0{fill:#4E9BE0}.s1{fill:#F0834F}.s2{fill:#3ECF9A}
}`

// legend lists the libraries in slot order, once each.
func legendOf(groups []group) []struct {
	label string
	slot  int
} {
	names := map[int]string{0: "kataras/jwt", 1: "golang-jwt", 2: "go-jose"}
	seen := make(map[int]bool)
	var items []struct {
		label string
		slot  int
	}

	for _, g := range groups {
		for _, b := range g.bars {
			if !seen[b.slot] {
				seen[b.slot] = true
				items = append(items, struct {
					label string
					slot  int
				}{names[b.slot], b.slot})
			}
		}
	}

	sort.Slice(items, func(i, j int) bool { return items[i].slot < items[j].slot })
	return items
}

// render draws the whole chart as one standalone SVG document.
func render(m metric, groups []group, platform string) []byte {
	rows := 0
	for _, g := range groups {
		rows += len(g.bars)
	}

	height := chartHeaderH + len(groups)*(chartGroupH+chartGroupGap) + rows*chartRowH + chartFooterH
	plotX := chartNameW
	plotWidth := float64(chartWidth - plotX - chartValueW - chartPadX)

	maxValue := 0.0
	for _, g := range groups {
		for _, b := range g.bars {
			maxValue = max(maxValue, b.value)
		}
	}

	var svg strings.Builder
	aria := m.title + ", " + m.subtitle
	fmt.Fprintf(&svg, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="%s">`+"\n",
		chartWidth, height, chartWidth, height, xmlEscape(aria))
	fmt.Fprintf(&svg, "<title>%s</title>\n", xmlEscape(aria))
	fmt.Fprintf(&svg, "<style>%s</style>\n", chartStyle)

	fmt.Fprintf(&svg, `<rect class="surface" x="0.5" y="0.5" width="%d" height="%d" rx="8"/>`+"\n",
		chartWidth-1, height-1)
	fmt.Fprintf(&svg, `<text class="title" x="%d" y="30">%s</text>`+"\n", chartPadX, xmlEscape(m.title))
	fmt.Fprintf(&svg, `<text class="subtitle" x="%d" y="49">%s</text>`+"\n", chartPadX, xmlEscape(m.subtitle))

	// Legend, laid out right to left from the right edge.
	x := float64(chartWidth - chartPadX)
	items := legendOf(groups)
	for i := len(items) - 1; i >= 0; i-- {
		x -= textWidth(items[i].label, 11.5)
		fmt.Fprintf(&svg, `<text class="legend" x="%.1f" y="30">%s</text>`+"\n", x, xmlEscape(items[i].label))
		x -= 16
		fmt.Fprintf(&svg, `<rect class="s%d" x="%.1f" y="21" width="10" height="10" rx="3"/>`+"\n", items[i].slot, x)
		x -= 18
	}

	y := float64(chartHeaderH)
	for _, g := range groups {
		fmt.Fprintf(&svg, `<text class="group" x="%d" y="%.1f">%s</text>`+"\n",
			chartPadX, y+13, xmlEscape(strings.ToUpper(g.title)))
		y += chartGroupH

		top := y
		for _, b := range g.bars {
			barY := y + float64(chartRowH-chartBarH)/2
			textY := barY + float64(chartBarH)/2 + 4.25

			width := 2.0
			if maxValue > 0 {
				width = max(2, b.value/maxValue*plotWidth)
			}

			fmt.Fprintf(&svg, `<text class="name" text-anchor="end" x="%d" y="%.2f">%s</text>`+"\n",
				plotX-10, textY, xmlEscape(b.name))
			fmt.Fprintf(&svg, `<path class="s%d" d="%s"/>`+"\n", b.slot, barPath(float64(plotX), barY, width, chartBarH))
			fmt.Fprintf(&svg, `<text class="value" x="%.1f" y="%.2f">%s</text>`+"\n",
				float64(plotX)+width+8, textY, xmlEscape(b.label))

			y += chartRowH
		}

		fmt.Fprintf(&svg, `<line class="baseline" x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f"/>`+"\n",
			float64(plotX)+0.5, top-4, float64(plotX)+0.5, y+2)
		y += chartGroupGap
	}

	if platform != "" {
		fmt.Fprintf(&svg, `<text class="footer" x="%d" y="%.1f">%s</text>`+"\n",
			chartPadX, y+14, xmlEscape(platform))
	}

	svg.WriteString("</svg>\n")
	return []byte(svg.String())
}

// barPath draws a horizontal bar with a rounded data end and a square baseline end.
func barPath(x, y, width, height float64) string {
	r := min(4.0, width/2)

	return fmt.Sprintf("M%.1f,%.1f h%.1f a%.1f,%.1f 0 0 1 %.1f,%.1f v%.1f a%.1f,%.1f 0 0 1 %.1f,%.1f h%.1f z",
		x, y, width-r, r, r, r, r, height-2*r, r, r, -r, r, -(width - r))
}

// textWidth approximates the rendered width of s at the given size, which is enough to lay
// out the legend and reserve room for a label.
func textWidth(s string, size float64) float64 {
	return float64(len(s)) * size * 0.58
}

// thousands formats a value as a grouped integer: 2447 becomes "2,447".
func thousands(v float64) string {
	s := strconv.FormatFloat(v, 'f', 0, 64)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}

	return s
}

func xmlEscape(s string) string { return xmlReplacer.Replace(s) }

var xmlReplacer = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	`"`, "&quot;",
	"'", "&apos;",
)
