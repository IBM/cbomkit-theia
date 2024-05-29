package filesystem

import (
	"io/fs"
	"os"
	"path/filepath"
)

type WalkDirFunc func(path string) error

type Filesystem interface {
	WalkDir(fn WalkDirFunc) (err error)
	ReadFile(path string) (content []byte, err error)
	GetDockerfilePath() (path string, ok bool)
}

type PlainFilesystem struct { // implements Filesystem
	rootPath string
}

func NewPlainFilesystem(rootPath string) PlainFilesystem {
	return PlainFilesystem{
		rootPath: rootPath,
	}
}

func (plainFilesystem PlainFilesystem) WalkDir(fn WalkDirFunc) error {
	return filepath.WalkDir(plainFilesystem.rootPath, func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}

		return fn(path)
	})
}

func (plainFilesystem PlainFilesystem) ReadFile(path string) ([]byte, error) {
	contentBytes, err := os.ReadFile(path)
	return contentBytes, err
}

func (plainFilesystem PlainFilesystem) GetDockerfilePath() (path string, ok bool) {
	return "", false
}
