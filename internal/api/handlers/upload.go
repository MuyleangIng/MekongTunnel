package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
)

// UploadHandler handles file uploads for verification documents.
type UploadHandler struct {
	// UploadDir is the directory where files are stored.
	UploadDir string
	// BaseURL is the public base URL used to build download links (e.g. http://localhost:8080).
	BaseURL string
}

// allowed MIME types and their extensions
var allowedMIME = map[string]string{
	"image/jpeg": ".jpg",
	"image/png":  ".png",
	"image/gif":  ".gif",
	"image/webp": ".webp",
	"application/pdf": ".pdf",
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
	"application/msword": ".doc",
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":              ".xlsx",
	"application/vnd.openxmlformats-officedocument.presentationml.presentation":      ".pptx",
	"application/vnd.ms-powerpoint": ".ppt",
}

const maxUploadSize = 10 << 20 // 10 MB

// Upload handles POST /api/upload — multipart/form-data with field "file".
func (h *UploadHandler) Upload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		response.BadRequest(w, "file too large (max 10 MB)")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		response.BadRequest(w, "missing 'file' field in form")
		return
	}
	defer file.Close()

	// Detect MIME type from first 512 bytes
	buf := make([]byte, 512)
	n, _ := file.Read(buf)
	mime := http.DetectContentType(buf[:n])
	// Seek back
	if seeker, ok := file.(io.Seeker); ok {
		seeker.Seek(0, io.SeekStart)
	}

	// Also accept MIME from Content-Type header if sniffing returns generic octet-stream
	if mime == "application/octet-stream" {
		ct := header.Header.Get("Content-Type")
		if ct != "" {
			mime = strings.Split(ct, ";")[0]
		}
	}

	ext, ok := allowedMIME[mime]
	if !ok {
		// Fall back to extension from original filename
		orig := strings.ToLower(filepath.Ext(header.Filename))
		for _, e := range allowedMIME {
			if e == orig {
				ext = orig
				ok = true
				break
			}
		}
	}
	if !ok {
		response.BadRequest(w, fmt.Sprintf("unsupported file type (%s)", mime))
		return
	}

	// Ensure upload directory exists
	if err := os.MkdirAll(h.UploadDir, 0755); err != nil {
		response.InternalError(w, err)
		return
	}

	// Generate random filename
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	filename := hex.EncodeToString(randBytes) + ext

	dest := filepath.Join(h.UploadDir, filename)
	out, err := os.Create(dest)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	defer out.Close()

	if _, err := io.Copy(out, file); err != nil {
		os.Remove(dest)
		response.InternalError(w, err)
		return
	}

	url := fmt.Sprintf("%s/api/uploads/%s", h.BaseURL, filename)
	response.Success(w, map[string]string{
		"url":      url,
		"filename": filename,
		"original": header.Filename,
	})
}

// ServeFile handles GET /api/uploads/{filename} — serves the stored file.
func (h *UploadHandler) ServeFile(w http.ResponseWriter, r *http.Request) {
	filename := r.PathValue("filename")
	if filename == "" || strings.Contains(filename, "..") || strings.Contains(filename, "/") {
		response.BadRequest(w, "invalid filename")
		return
	}
	http.ServeFile(w, r, filepath.Join(h.UploadDir, filename))
}
