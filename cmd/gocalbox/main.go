package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/nobletk/gocalbox/internal/sandbox"
)

type ClientFileInfo struct {
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	IsDir bool   `json:"isDir"`
}

type DeleteRequest struct {
	Path string `json:"path"`
}

type MoveRequest struct {
	OldPath string `json:"oldPath"`
	NewPath string `json:"newPath"`
}

type CreateFolderRequest struct {
	Name       string `json:"name"`
	TargetPath string `json:"targetPath"`
}

func main() {
	port := flag.String("port", "8080", "Port to run the server on")
	rootDir := flag.String("root", ".", "The local directory to sandbox and serve")
	flag.Parse()

	if info, err := os.Stat(*rootDir); err != nil || !info.IsDir() {
		log.Fatalf("Fatal Error: Root directory '%s' does not exist or is not a directory.", *rootDir)
	}

	http.Handle("/", eventMiddleware(http.FileServer(http.Dir("web"))))

	fileSystem := os.DirFS(*rootDir)
	http.Handle("/files/", http.StripPrefix("/files/", http.FileServer(http.FS(fileSystem))))

	http.HandleFunc("/api/files", handleListFiles(*rootDir))
	http.HandleFunc("/api/upload", handleUpload(*rootDir))
	http.HandleFunc("/api/fs/delete", handleDelete(*rootDir))
	http.HandleFunc("/api/fs/rename", handleMoveRename(*rootDir))
	http.HandleFunc("/api/fs/move", handleMoveRename(*rootDir))
	http.HandleFunc("/api/fs/mkdir", handleCreateFolder(*rootDir))

	log.Printf("Starting secure read-only server on http://localhost:%s", *port)
	log.Printf("Sandboxing directory: %s", *rootDir)

	if err := http.ListenAndServe(":"+*port, nil); err != nil {
		log.Fatalf("Server crashed: %v", err)
	}
}

func eventMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Event [FileRequested]: %s %s", r.Method, r.URL.Path)

		next.ServeHTTP(w, r)
	})
}

func handleListFiles(rootDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestedPath := r.URL.Query().Get("path")
		log.Printf("Event [FileListRequested]: GET /api/files?path=%s", requestedPath)

		targetDir, err := sandbox.SecureJoin(rootDir, requestedPath)
		if err != nil {
			log.Printf("SECURITY ALERT: Blocked directory read attempt: %v", err)
			http.Error(w, "Invalid directory path", http.StatusForbidden)
			return
		}

		entries, err := os.ReadDir(targetDir)
		if err != nil {
			http.Error(w, "Failed to read directory", http.StatusInternalServerError)
			return
		}

		var files []ClientFileInfo
		for _, entry := range entries {
			sysInfo, err := entry.Info()
			if err != nil {
				continue
			}

			files = append(files, ClientFileInfo{
				Name:  entry.Name(),
				Size:  sysInfo.Size(),
				IsDir: entry.IsDir(),
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(files)
	}
}

func handleUpload(rootDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Event [UploadInitiated]: %s %s", r.Method, r.URL.Path)

		requestedPath := r.URL.Query().Get("path")

		if err := r.ParseMultipartForm(50 << 20); err != nil {
			log.Printf("ParseMultipartForm error: %v", err)
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		file, header, err := r.FormFile("myFile")
		if err != nil {
			log.Printf("FormFile error: %v", err)
			http.Error(w, "Failed to read file", http.StatusBadRequest)
			return
		}
		defer file.Close()

		logicalPath := filepath.Join(requestedPath, header.Filename)

		destinationPath, err := sandbox.SecureJoin(rootDir, logicalPath)
		if err != nil {
			log.Printf("SECURITY ALERT: Blocked upload attempt: %v", err)
			http.Error(w, "Invalid file path", http.StatusForbidden)
			return
		}

		safeDestinationPath := generateUniquePath(destinationPath)

		dst, err := os.Create(safeDestinationPath)
		if err != nil {
			log.Printf("Failed to create file on disk: %v", err)
			http.Error(w, "Failed to save file", http.StatusInternalServerError)
			return
		}
		defer dst.Close()

		if _, err := io.Copy(dst, file); err != nil {
			log.Printf("Error writing file to disk: %v", err)
			http.Error(w, "Errot writing file to disk", http.StatusInternalServerError)
			return
		}

		log.Printf("File successfully saved to: %s", safeDestinationPath)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("File uploaded successfully!"))
	}
}

func handleDelete(rootDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req DeleteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("Failed to decode delete request: %v", err)
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		log.Printf("Event [DeleteRequested]: target=%s", req.Path)

		targetPath, err := sandbox.SecureJoin(rootDir, req.Path)
		if err != nil {
			log.Printf("SECURITY ALERT: Blocked delete attempt on: %v", err)
			http.Error(w, "Invalid file path", http.StatusForbidden)
			return
		}

		if _, err := os.Stat(targetPath); os.IsNotExist(err) {
			log.Printf("Delete aborted: File does not exit: %s", targetPath)
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}

		if err := os.RemoveAll(targetPath); err != nil {
			log.Printf("Failed to delete file on disk: %v", err)
			http.Error(w, "Failed to delete file", http.StatusInternalServerError)
			return
		}

		log.Printf("Successfully deleted: %s", targetPath)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("File deleted successfully"))
	}
}

func handleMoveRename(rootDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req MoveRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("Failed to decode move/rename request: %v", err)
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		log.Printf("Event [MoveRenameRequested]: %s -> %s", req.OldPath, req.NewPath)

		oldTarget, err := sandbox.SecureJoin(rootDir, req.OldPath)
		if err != nil {
			log.Printf("SECURITY ALERT: Blocked invalid source path: %v", err)
			http.Error(w, "Invalid source path", http.StatusForbidden)
			return
		}

		newTarget, err := sandbox.SecureJoin(rootDir, req.NewPath)
		if err != nil {
			log.Printf("SECURITY ALERT: Blocked invalid destination path: %v", err)
			http.Error(w, "Invalid destination path", http.StatusForbidden)
			return
		}

		if _, err := os.Stat(oldTarget); os.IsNotExist(err) {
			log.Printf("Aborted: Source file does not exist: %s", oldTarget)
			http.Error(w, "Source file not found", http.StatusNotFound)
			return
		}

		if _, err := os.Stat(newTarget); err == nil {
			log.Printf("Aborted: Destination file already exists: %s", newTarget)
			http.Error(w, "Destination already exists", http.StatusConflict)
			return
		}

		targetDir := filepath.Dir(newTarget)
		if info, err := os.Stat(targetDir); os.IsNotExist(err) || !info.IsDir() {
			log.Printf("Aborted: Target folder does not exist: %s", targetDir)
			http.Error(w, "Target folder does not exist", http.StatusBadRequest)
			return
		}

		if err := os.Rename(oldTarget, newTarget); err != nil {
			log.Printf("Failed to move/rename file on disk: %v", err)
			http.Error(w, "Failed to perform operation", http.StatusInternalServerError)
			return
		}

		log.Printf("Successfully moved/renamed from: %s -> %s", oldTarget, newTarget)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Operation successful"))
	}
}

func handleCreateFolder(rootDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req CreateFolderRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("Failed to decode create folder request: %v", err)
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		log.Printf("Event [CreateFolderRequested]: creating '%s' inside '%s'", req.Name, req.TargetPath)

		logicalPath := filepath.Join(req.TargetPath, req.Name)

		newTarget, err := sandbox.SecureJoin(rootDir, logicalPath)
		if err != nil {
			log.Printf("SECURITY ALERT: Blocked invalid path: %v", err)
			http.Error(w, "Invalid directory path", http.StatusForbidden)
			return
		}

		if err := os.Mkdir(newTarget, 0755); err != nil {
			if os.IsExist(err) {
				log.Printf("Aborted: Folder already exists: %v", err)
				http.Error(w, "Folder already exists", http.StatusConflict)
				return
			}
			log.Printf("Failed to create directory on disk: %v", err)
			http.Error(w, "Failed to create folder", http.StatusInternalServerError)
			return
		}

		log.Printf("Successfully created new folder: %s", newTarget)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Folder created successfully"))
	}
}

func generateUniquePath(targetPath string) string {
	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		return targetPath
	}

	dir := filepath.Dir(targetPath)
	ext := filepath.Ext(targetPath)

	baseName := strings.TrimSuffix(filepath.Base(targetPath), ext)

	counter := 1
	for {
		newName := fmt.Sprintf("%s (%d)%s", baseName, counter, ext)
		newPath := filepath.Join(dir, newName)

		if _, err := os.Stat(newPath); os.IsNotExist(err) {
			return newPath
		}
		counter++
	}
}
