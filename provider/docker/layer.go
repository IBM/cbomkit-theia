package docker

import (
	"errors"
	"fmt"
	"io"
	"log/slog"

	"ibm/container_cryptography_scanner/provider/filesystem"
	scanner_errors "ibm/container_cryptography_scanner/scanner/errors"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree/filenode"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type Layer struct { // implements Filesystem
	index int
	image ActiveImage
}

func (layer Layer) WalkDir(fn filesystem.SimpleWalkDirFunc) error {
	return layer.image.Layers[layer.index].SquashedTree.Walk(
		func(path file.Path, f filenode.FileNode) error {
			if f.FileType == file.TypeDirectory {
				return nil
			}

			err := fn(string(path))

			if errors.Is(err, scanner_errors.ErrParsingFailedAlthoughChecked) {
				slog.Warn(err.Error())
				return nil
			} else {
				return err
			}
		}, nil)
}

func (layer Layer) ReadFile(path string) ([]byte, error) {
	readCloser, err := layer.image.Layers[layer.index].OpenPathFromSquash(file.Path(path))
	if err != nil {
		return []byte{}, err
	}

	defer readCloser.Close()

	contentBytes, err := io.ReadAll(readCloser)

	return contentBytes, err
}

func (layer Layer) GetConfig() (config v1.Config, ok bool) {
	return layer.image.GetConfig()
}

func (layer Layer) GetIdentifier() string {
	return fmt.Sprintf("Docker Image Layer (id:%v, layer:%v)", layer.image.id, layer.index)
}