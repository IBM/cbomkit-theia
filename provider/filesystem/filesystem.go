package filesystem

import (
	go_errors "errors"
	"fmt"
	scanner_errors "ibm/container-image-cryptography-scanner/scanner/errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// A simple interface for a function to walk directories
type SimpleWalkDirFunc func(filesystem Filesystem, path string) error

// Filesystem interface is mainly used to interact with all types of possible data source (e.g. directories, docker images etc.); for images this represents a squashed layer
type Filesystem interface {
	WalkDir(fn SimpleWalkDirFunc) (err error)         // Walk the full filesystem using the SimpleWalkDirFunc fn
	ReadFile(path string) (content []byte, err error) // Read a specific file with a path from root of the filesystem
	GetConfig() (config v1.Config, ok bool)           // Get a config of this filesystem in container image format (if it exists)
	GetIdentifier() string                            // Identifier for this specific filesystem; can be used for logging
}

// Simple plain filesystem that is constructed from the directory
type PlainFilesystem struct { // implements Filesystem
	rootPath string
}

// Get a new PlainFilesystem from rootPath
func NewPlainFilesystem(rootPath string) PlainFilesystem {
	return PlainFilesystem{
		rootPath: rootPath,
	}
}

// Walk the whole PlainFilesystem using fn
func (plainFilesystem PlainFilesystem) WalkDir(fn SimpleWalkDirFunc) error {
	return filepath.WalkDir(plainFilesystem.rootPath, func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}

		relativePath, err := filepath.Rel(plainFilesystem.rootPath, path)

		if err != nil {
			panic(err)
		}

		err = fn(plainFilesystem, relativePath)

		if go_errors.Is(err, scanner_errors.ErrParsingFailedAlthoughChecked) {
			slog.Warn(err.Error())
			return nil
		} else {
			return err
		}
	})
}

// Read a file from this filesystem; path should be relative to PlainFilesystem.rootPath
func (plainFilesystem PlainFilesystem) ReadFile(path string) ([]byte, error) {
	contentBytes, err := os.ReadFile(filepath.Join(plainFilesystem.rootPath, path))
	return contentBytes, err
}

// A plain directory does not have filesystem, so we return an empty object and false
func (plainFilesystem PlainFilesystem) GetConfig() (config v1.Config, ok bool) {
	return v1.Config{}, false
}

// Get a unique string for this PlainFilesystem; can be used for logging etc.
func (plainFilesystem PlainFilesystem) GetIdentifier() string {
	return fmt.Sprintf("Plain Filesystem (%v)", plainFilesystem.rootPath)
}
