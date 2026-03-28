package web

import (
	"mime"
	"net/http"
	"path/filepath"
	"strconv"

	gitb "github.com/charmbracelet/soft-serve/git"
	"github.com/charmbracelet/soft-serve/pkg/access"
	"github.com/gorilla/mux"
)

// getRawBlob serves the raw content of a single file at a given ref and path.
// It is registered as GET /{repo}/raw/{ref}/{filepath}.
//
// The Accept header controls delivery:
//   - "application/octet-stream" → Content-Disposition: attachment (download)
//   - anything else              → Content-Type inferred from extension or
//     binary detection (text/plain for text, application/octet-stream for binary)
func getRawBlob(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	dir := vars["dir"]
	ref := vars["ref"]
	filePath := vars["filepath"]

	ctx := r.Context()
	if access.FromContext(ctx) < access.ReadOnlyAccess {
		renderUnauthorized(w, r)
		return
	}

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

	if te.Type() != "blob" {
		// Path points to a tree (directory), not a file.
		renderNotFound(w, r)
		return
	}

	bts, err := te.Contents()
	if err != nil {
		renderInternalServerError(w, r)
		return
	}

	// Determine Content-Type.
	contentType := mime.TypeByExtension(filepath.Ext(filePath))
	if contentType == "" {
		isBin, _ := te.File().IsBinary()
		if isBin {
			contentType = "application/octet-stream"
		} else {
			contentType = "text/plain; charset=utf-8"
		}
	}

	// If the client explicitly requests a binary stream, serve as download.
	if r.Header.Get("Accept") == "application/octet-stream" {
		contentType = "application/octet-stream"
		w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(filePath))
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(bts)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bts)
}
