package web

import (
	"bytes"
	"mime"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	gitb "github.com/charmbracelet/soft-serve/git"
	"github.com/gorilla/mux"
)

// maxRawBlobSize is the largest blob that getRawBlob will read into memory.
// Requests for blobs exceeding this size receive HTTP 413.
const maxRawBlobSize = 32 * 1024 * 1024 // 32 MiB

// getRawBlob serves the raw content of a single file at a given ref and path.
// It is registered as GET /{repo}/raw/{ref}/{filepath}.
//
// Access control is enforced by the withAccess middleware that wraps this
// handler: unauthenticated users see 401, insufficient-access users see 404
// (to avoid leaking repo existence). The handler never re-checks access.
//
// The Accept header controls delivery:
//   - "application/octet-stream" → Content-Disposition: attachment (download)
//   - anything else              → Content-Type inferred from extension or
//     binary detection (text/plain for text, application/octet-stream for binary)
//
// Note: dir is constructed and sanitised by the withParams middleware and must
// not be derived locally inside this handler.
func getRawBlob(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dir := vars["dir"]
	ref := vars["ref"]
	filePath := vars["filepath"]

	if filePath == "" {
		renderBadRequest(w, r)
		return
	}

	repo, err := gitb.Open(dir)
	if err != nil {
		renderNotFound(w, r)
		return
	}

	// Resolve HEAD when no ref is given.
	if ref == "" || ref == "HEAD" {
		head, err := repo.HEAD()
		if err != nil {
			renderNotFound(w, r)
			return
		}
		ref = head.ID
	}

	tree, err := repo.LsTree(ref)
	if err != nil {
		renderNotFound(w, r)
		return
	}

	te, err := tree.TreeEntry(filePath)
	if err != nil {
		renderNotFound(w, r)
		return
	}

	// Must be a blob (file), not a tree (directory).
	if te.Type() != "blob" {
		renderNotFound(w, r)
		return
	}

	// Guard against OOM/DoS from very large blobs.
	if te.Size() > maxRawBlobSize {
		renderStatus(http.StatusRequestEntityTooLarge)(w, r)
		return
	}

	bts, err := te.Contents()
	if err != nil {
		renderInternalServerError(w, r)
		return
	}

	// Determine Content-Type from extension first, then fall back to binary
	// detection using the bytes already in memory (avoids a second git subprocess).
	contentType := mime.TypeByExtension(filepath.Ext(filePath))
	if contentType == "" {
		isBin, _ := gitb.IsBinary(bytes.NewReader(bts))
		if isBin {
			contentType = "application/octet-stream"
		} else {
			contentType = "text/plain; charset=utf-8"
		}
	}

	// Sanitise: downgrade any MIME type that a browser will execute scripts from.
	// This prevents stored-XSS when an attacker pushes an .html/.svg/.js file.
	contentType = sanitizeMIME(contentType)

	// X-Content-Type-Options prevents browsers from sniffing and upgrading the type.
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// If the client explicitly requests a binary stream, serve as download.
	if r.Header.Get("Accept") == "application/octet-stream" {
		contentType = "application/octet-stream"
		// Quote the filename per RFC 6266 §4.3 and escape embedded quotes.
		safeName := strings.ReplaceAll(filepath.Base(filePath), `"`, `\"`)
		w.Header().Set("Content-Disposition", `attachment; filename="`+safeName+`"`)
	}

	// Mutable refs (branch names, tags) must not be cached by proxies.
	// A future improvement could set max-age for immutable SHA refs.
	w.Header().Set("Cache-Control", "no-store")

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(bts)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bts)
}

// sanitizeMIME downgrades MIME types that a browser will execute scripts from
// to text/plain, preventing stored-XSS attacks via pushed files.
func sanitizeMIME(ct string) string {
	// Strip parameters for comparison (e.g. "text/html; charset=utf-8" → "text/html").
	base := ct
	if i := strings.Index(ct, ";"); i != -1 {
		base = strings.TrimSpace(ct[:i])
	}
	base = strings.ToLower(base)

	switch {
	case base == "text/html",
		base == "text/xhtml",
		base == "application/xhtml+xml",
		strings.HasSuffix(base, "/javascript"),
		strings.HasSuffix(base, "+xml"), // SVG, MathML, XHTML variants
		base == "application/xml",
		base == "text/xml":
		return "text/plain; charset=utf-8"
	}
	return ct
}
