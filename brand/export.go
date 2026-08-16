package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Where the small-size cut takes over.
//
// Below this the three teeth of the full mark land within a pixel of each other and merge
// into one wedge, and the ring's hole closes. Verified by rendering both cuts at 16, 24,
// 32 and 48 and looking at them magnified, not by picking a round number.
//
// Do not "simplify" this away by exporting one cut at every size. The whole reason two
// cuts exist is that the answer differs above and below 48.
const smallCutBelow = 48

// markSizes are the square PNG exports.
var markSizes = []int{16, 32, 48, 64, 128, 256, 512}

// faviconSizes are the frames packed into favicon.ico. Windows and older browsers pick
// from these; everything modern takes the 32.
var faviconSizes = []int{16, 32, 48}

// bodyForSize returns the cut that belongs at a given export size.
func bodyForSize(size int, g Ground) string {
	if size < smallCutBelow {
		return markSmallBody(g.blue())
	}
	return markBody(g.blue())
}

func export(browser, exportDir string) error {
	if err := os.MkdirAll(exportDir, 0o755); err != nil {
		return err
	}

	tmp, err := os.MkdirTemp("", "jwt-brand-*")
	if err != nil {
		return err
	}
	// Nothing here can act on a failed cleanup: the exports are already written, the
	// directory is the operating system's own temporary tree, and returning an error for
	// it would fail a run that produced every file it was asked for.
	defer func() { _ = os.RemoveAll(tmp) }()

	// Square marks, on a transparent ground.
	for _, size := range markSizes {
		name := fmt.Sprintf("jwt-mark-%d.png", size)
		out := filepath.Join(exportDir, name)

		inner := svgDoc("0 0 24 24", "jwt", bodyForSize(size, Light))
		if err = rasterize(browser, tmp, inner, size, size, out); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}

		cut := "full"
		if size < smallCutBelow {
			cut = "small"
		}
		fmt.Printf("wrote %s (%s cut)\n", out, cut)
	}

	// The on-dark mark, for anywhere that composites onto the dark field itself.
	for _, size := range []int{128, 256} {
		name := fmt.Sprintf("jwt-mark-on-dark-%d.png", size)
		out := filepath.Join(exportDir, name)

		inner := svgDoc("0 0 24 24", "jwt", bodyForSize(size, Dark))
		if err = rasterize(browser, tmp, inner, size, size, out); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		fmt.Println("wrote", out)
	}

	// The lockup, on both grounds. The on-dark one is not optional: the wordmark is
	// Aegean on light and Marble on dark, so the light PNG dropped onto a dark field is
	// blue-on-navy and close to unreadable.
	for _, g := range []Ground{Light, Dark} {
		suffix := ""
		if g == Dark {
			suffix = "-on-dark"
		}

		for _, size := range []int{320, 640} {
			name := fmt.Sprintf("jwt-lockup%s-%d.png", suffix, size)
			out := filepath.Join(exportDir, name)

			height := size * 28 / 92
			if err = rasterize(browser, tmp, lockupSVG(g), size, height, out); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			fmt.Println("wrote", out)
		}
	}

	// The hero, which doubles as the social card.
	for _, width := range []int{640, 1280} {
		name := fmt.Sprintf("jwt-hero-%d.png", width)
		out := filepath.Join(exportDir, name)

		if err = rasterize(browser, tmp, heroSVG(), width, width/2, out); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		fmt.Println("wrote", out)
	}

	return writeFavicon(browser, tmp, exportDir)
}

// rasterize renders an SVG at an exact pixel size through a headless browser.
//
// The SVG goes into a page sized to match, with a transparent background, and the browser
// screenshots the viewport. --default-background-color=00000000 is what keeps the corners
// transparent; without it every export arrives on opaque white and the favicon has a box
// around it.
func rasterize(browser, tmp, svg string, w, h int, out string) error {
	page := fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"><style>
html,body{margin:0;padding:0;background:transparent}
svg{display:block;width:%dpx;height:%dpx}
</style></head><body>%s</body></html>`, w, h, svg)

	pagePath := filepath.Join(tmp, "page.html")
	if err := os.WriteFile(pagePath, []byte(page), 0o644); err != nil {
		return err
	}

	absOut, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	absPage, err := filepath.Abs(pagePath)
	if err != nil {
		return err
	}

	cmd := exec.Command(browser,
		"--headless=new",
		"--disable-gpu",
		"--no-sandbox",
		"--hide-scrollbars",
		"--force-device-scale-factor=1",
		"--default-background-color=00000000",
		"--user-data-dir="+filepath.Join(tmp, "profile"),
		"--screenshot="+absOut,
		fmt.Sprintf("--window-size=%d,%d", w, h),
		"file:///"+filepath.ToSlash(absPage),
	)

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w: %s", browser, err, output)
	}

	if _, err = os.Stat(absOut); err != nil {
		return fmt.Errorf("the browser reported success but wrote no file: %w", err)
	}

	return nil
}

// writeFavicon packs PNG frames into an .ico.
//
// ICO is a directory of images with a 6 byte header and a 16 byte entry each. Modern
// decoders read PNG frames directly, so there is no BMP conversion to do and no need for a
// dependency to do it.
func writeFavicon(browser, tmp, exportDir string) error {
	type frame struct {
		size int
		data []byte
	}

	frames := make([]frame, 0, len(faviconSizes))
	for _, size := range faviconSizes {
		path := filepath.Join(tmp, fmt.Sprintf("favicon-%d.png", size))

		inner := svgDoc("0 0 24 24", "jwt", bodyForSize(size, Light))
		if err := rasterize(browser, tmp, inner, size, size, path); err != nil {
			return fmt.Errorf("favicon %d: %w", size, err)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		frames = append(frames, frame{size: size, data: data})
	}

	var buf bytes.Buffer

	// A half-written header is a corrupt .ico that decoders report as a broken image and
	// nothing else, so every field is checked. put keeps the first failure and skips the
	// rest, which leaves the layout below readable as a description of the format instead
	// of a run of eight if statements.
	var writeErr error
	put := func(v any) {
		if writeErr == nil {
			writeErr = binary.Write(&buf, binary.LittleEndian, v)
		}
	}

	// ICONDIR: reserved, type 1 (icon), count.
	put(uint16(0))
	put(uint16(1))
	put(uint16(len(frames)))

	offset := 6 + 16*len(frames)
	for _, f := range frames {
		// A dimension of 0 means 256 in this format. None of these reach it, but the
		// conversion is written out so that adding a 256 frame later does not surprise
		// anyone.
		dim := byte(f.size)
		if f.size >= 256 {
			dim = 0
		}

		put(dim)                 // width
		put(dim)                 // height
		put(byte(0))             // palette size, 0 for truecolour
		put(byte(0))             // reserved
		put(uint16(1))           // colour planes
		put(uint16(32))          // bits per pixel
		put(uint32(len(f.data))) // bytes in this frame
		put(uint32(offset))      // where it starts
		offset += len(f.data)
	}

	if writeErr != nil {
		return fmt.Errorf("favicon: writing the ICO directory: %w", writeErr)
	}

	for _, f := range frames {
		buf.Write(f.data)
	}

	out := filepath.Join(exportDir, "favicon.ico")
	if err := os.WriteFile(out, buf.Bytes(), 0o644); err != nil {
		return err
	}

	fmt.Printf("wrote %s (%d frames: %v, small cut below %d)\n", out, len(frames), faviconSizes, smallCutBelow)
	return nil
}

// findBrowser locates a Chromium-family browser.
func findBrowser() (string, error) {
	names := []string{"chrome", "google-chrome", "chromium", "chromium-browser", "msedge"}
	for _, name := range names {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}

	var candidates []string
	switch runtime.GOOS {
	case "windows":
		for _, root := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("LOCALAPPDATA")} {
			if root == "" {
				continue
			}
			candidates = append(candidates,
				filepath.Join(root, "Google", "Chrome", "Application", "chrome.exe"),
				filepath.Join(root, "Microsoft", "Edge", "Application", "msedge.exe"),
			)
		}
	case "darwin":
		candidates = []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		}
	default:
		candidates = []string{
			"/usr/bin/google-chrome",
			"/usr/bin/chromium",
			"/usr/bin/chromium-browser",
			"/snap/bin/chromium",
		}
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", errors.New("no Chromium-family browser found on PATH or at the usual locations (" +
		strings.Join(names, ", ") + ")")
}
