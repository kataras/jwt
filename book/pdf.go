package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// printToPDF renders the book's HTML to PDF through a headless browser.
//
// This drives the browser over the DevTools protocol rather than shelling out to
// --print-to-pdf, and the reason is worth recording because the simpler version looks like
// it works.
//
// The pagination polyfill rewrites the whole document into pages after load, and on a book
// this size that takes several seconds of layout. --print-to-pdf prints at the load event,
// long before that finishes, so it produces a single blank page. The documented workaround,
// --virtual-time-budget, is unreliable here: measured on this book, a budget of 120 seconds
// produced 53 KB of output while 300 and 600 seconds both produced the same 1230-byte blank
// page. Virtual time advances when the task queue empties, and the polyfill's work does not
// keep it busy in the way that assumes.
//
// So: wait for the polyfill to stop producing pages, then print. That is a condition you can
// actually observe.
func printToPDF(browser, htmlPath, pdfPath string) error {
	absHTML, err := filepath.Abs(htmlPath)
	if err != nil {
		return err
	}
	absPDF, err := filepath.Abs(pdfPath)
	if err != nil {
		return err
	}

	profile, err := os.MkdirTemp("", "jwt-book-*")
	if err != nil {
		return err
	}
	// The browser profile is scratch space in the operating system's temporary tree, and
	// by the time this runs the PDF is either written or the run has already failed for a
	// reason worth reporting. Failing the build over a directory that could not be swept
	// up would replace a real result with a bookkeeping complaint.
	defer func() { _ = os.RemoveAll(profile) }()

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(browser),
		chromedp.UserDataDir(profile),
		chromedp.NoSandbox,
		chromedp.DisableGPU,
		chromedp.Flag("hide-scrollbars", true),
		chromedp.Flag("run-all-compositor-stages-before-draw", true),
	)

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	ctx, cancelTimeout := context.WithTimeout(ctx, 10*time.Minute)
	defer cancelTimeout()

	fmt.Println("book: paginating, which takes about a minute on a book this size")

	var pdf []byte
	var pages int

	err = chromedp.Run(ctx,
		chromedp.Navigate("file:///"+filepath.ToSlash(absHTML)),
		chromedp.WaitVisible(".pagedjs_page", chromedp.ByQuery),
		waitForPagination(&pages),
		chromedp.ActionFunc(func(ctx context.Context) error {
			var err error
			// The stylesheet already sets the page size and margins through @page, and
			// the polyfill has laid the content out to match, so this must not impose its
			// own. PreferCSSPageSize is what keeps the two in step.
			pdf, _, err = page.PrintToPDF().
				WithPrintBackground(true).
				WithPreferCSSPageSize(true).
				Do(ctx)
			return err
		}),
	)
	if err != nil {
		return fmt.Errorf("printing to PDF: %w", err)
	}

	if err = os.WriteFile(absPDF, pdf, 0o644); err != nil {
		return err
	}

	// A PDF of a few kilobytes is a blank page, which is what a pagination failure looks
	// like. Catch it here rather than letting somebody discover it after publishing.
	const suspicious = 64 << 10
	if len(pdf) < suspicious {
		return fmt.Errorf("the PDF is only %d bytes from %d pages, which almost certainly "+
			"means the pagination did not finish; check assets/paged.polyfill.js", len(pdf), pages)
	}

	fmt.Printf("book: paginated to %d pages\n", pages)
	return nil
}

// waitForPagination blocks until the polyfill stops adding pages.
//
// There is no event to wait on that is reliable across versions, so this watches the page
// count and calls it finished once the number has held still for three consecutive checks.
// A book that is still laying out adds pages steadily, so a count that stops moving means
// the work is done rather than merely slow.
func waitForPagination(out *int) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		const (
			interval  = 500 * time.Millisecond
			stableFor = 3
		)

		last, stable := -1, 0

		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(interval):
			}

			var count int
			if err := chromedp.Evaluate(`document.querySelectorAll('.pagedjs_page').length`, &count).Do(ctx); err != nil {
				return err
			}

			if count == last && count > 0 {
				stable++
				if stable >= stableFor {
					*out = count
					return nil
				}
				continue
			}

			last, stable = count, 0
		}
	})
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
