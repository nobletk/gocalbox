package httpapi

import (
	"errors"
	"io"
	"log"
	"net/http"
	"path"
)

func (a *api) handleListFiles(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}

	entries, err := a.files.List(r.Context(), r.URL.Query().Get("path"))
	if err != nil {
		writeError(w, r, err)
		return
	}

	files := make([]ClientFileInfo, 0, len(entries)) // [] rather than null when empty
	for _, e := range entries {
		files = append(files, ClientFileInfo{Name: e.Name, Size: e.Size, IsDir: e.IsDir})
	}
	writeJSON(w, http.StatusOK, files)
}

func (a *api) handleUpload(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) || !requireContentType(w, r, "multipart/form-data") {
		return
	}
	if a.maxUpload > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, a.maxUpload)
	}

	mr, err := r.MultipartReader()
	if err != nil {
		log.Printf("MultipartReader error: %v", err)
		writeErrorJSON(w, r, http.StatusBadRequest, "invalid_body", "Malformed multipart body")
		return
	}

	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				writeError(w, r, err)
				return
			}
			log.Printf("Failed to read multipart body: %v", err)
			writeErrorJSON(w, r, http.StatusBadRequest, "invalid_body", "Malformed multipart body")
			return
		}
		if part.FormName() != "myFile" || part.FileName() == "" {
			part.Close()
			continue
		}

		// FileName is already reduced to a base name by the standard library.
		stored, size, err := a.files.Create(r.Context(), r.URL.Query().Get("path"), part.FileName(), part)
		if err != nil {
			writeError(w, r, err)
			return
		}
		writeJSON(w, http.StatusCreated, PathResponse{Path: stored, Name: path.Base(stored), Size: size})
		return
	}

	writeErrorJSON(w, r, http.StatusBadRequest, "missing_file", `No file in form field "myFile"`)
}

func (a *api) handleDelete(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req DeleteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	deleted, err := a.files.Delete(r.Context(), req.Path)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, PathResponse{Path: deleted})
}

func (a *api) handleMove(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req MoveRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	moved, err := a.files.Move(r.Context(), req.OldPath, req.NewPath)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, PathResponse{Path: moved})
}

func (a *api) handleCreateFolder(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req CreateFolderRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	created, err := a.files.Mkdir(r.Context(), req.TargetPath, req.Name)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, PathResponse{Path: created})
}
