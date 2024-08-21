// Copyright 2024 IBM
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"errors"
	"fmt"
	"io"
	"log/slog"

	"ibm/container-image-cryptography-scanner/provider/filesystem"
	scanner_errors "ibm/container-image-cryptography-scanner/scanner/errors"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree/filenode"
	"github.com/anchore/stereoscope/pkg/image"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Struct to represent a single layer in an ActiveImage
type Layer struct { // implements Filesystem
	*image.Layer
	index int
	image *ActiveImage
}

// Walk all files in the squashed layer using fn
func (layer Layer) WalkDir(fn filesystem.SimpleWalkDirFunc) error {
	return layer.SquashedTree.Walk(
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

// Read a file from this layer
func (layer Layer) ReadFile(path string) ([]byte, error) {
	readCloser, err := layer.OpenPathFromSquash(file.Path(path))
	if err != nil {
		return []byte{}, err
	}

	defer readCloser.Close()

	contentBytes, err := io.ReadAll(readCloser)

	return contentBytes, err
}

// Get the image config
func (layer Layer) GetConfig() (config v1.Config, ok bool) {
	return layer.image.GetConfig()
}

// Get a unique string for this layer in the image; can be used for logging etc.
func (layer Layer) GetIdentifier() string {
	return fmt.Sprintf("Docker Image Layer (id:%v, layer:%v)", layer.image.id, layer.index)
}
