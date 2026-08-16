// Command brand generates every piece of art this project ships.
//
// The mark is defined once, in mark.go, and everything else here embeds that same
// definition: the on-dark variant, the monochrome variant, the lockup, the hero, and every
// PNG. Two copies of a logo drift, and the copy nobody regenerates is the one that ends up
// in the README.
//
// Run it from this directory:
//
//	cd brand && go run .
//
// It needs a Chromium-family browser on PATH, or at one of the usual install locations, to
// turn the SVGs into PNGs. Without one it writes the SVGs, says so, and exits without an
// error, so that a checkout with no browser can still regenerate the vector art.
//
// This is a separate Go module on purpose. The library itself has no dependencies and
// keeps none; a nested module is excluded from the parent, so nothing here can leak into
// go.mod. It happens to need no dependencies either, but that is not why it is separate.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	outDir := flag.String("out", ".", "directory to write the SVGs into")
	exportDir := flag.String("export", "export", "directory to write the PNGs into")
	svgOnly := flag.Bool("svg-only", false, "skip rasterization even if a browser is available")
	flag.Parse()

	if err := run(*outDir, *exportDir, *svgOnly); err != nil {
		fmt.Fprintln(os.Stderr, "brand:", err)
		os.Exit(1)
	}
}

func run(outDir, exportDir string, svgOnly bool) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	// The vector art. Everything here is derived from the same mark definition.
	files := map[string]string{
		"jwt-mark.svg":           markSVG(Light),
		"jwt-mark-on-dark.svg":   markSVG(Dark),
		"jwt-mark-small.svg":     markSmallSVG(Light),
		"jwt-mark-mono.svg":      markMonoSVG(),
		"jwt-lockup.svg":         lockupSVG(Light),
		"jwt-lockup-on-dark.svg": lockupSVG(Dark),
		"jwt-hero.svg":           heroSVG(),
	}

	for name, content := range files {
		path := filepath.Join(outDir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
		fmt.Println("wrote", path)
	}

	if svgOnly {
		fmt.Println("brand: -svg-only given, skipping the PNGs")
		return nil
	}

	browser, err := findBrowser()
	if err != nil {
		// Not an error. A checkout without a browser can still regenerate the vectors,
		// and the PNGs in export/ are committed.
		fmt.Println("brand:", err)
		fmt.Println("brand: SVGs written, PNGs skipped. Install Chrome or Edge to regenerate them.")
		return nil
	}
	fmt.Println("brand: rasterizing with", browser)

	return export(browser, exportDir)
}
