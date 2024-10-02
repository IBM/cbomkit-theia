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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/IBM/cbomkit-theia/provider/filesystem"

	"github.com/anchore/go-logger"
	"github.com/anchore/go-logger/adapter/logrus"
	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/docker/docker/api/types"
	docker_api_types_image "github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/archive"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Represents an active image (e.g. with an active client connection)
type ActiveImage struct {
	*image.Image
	id     string
	client *client.Client
}

// TearDown Defer to this function to destroy the ActiveImage after use
func (image ActiveImage) TearDown() {
	slog.Info("Removing Image", "id", image.id)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := image.Cleanup()
	if err != nil {
		panic(err)
	}

	_, err = image.client.ImageRemove(ctx, image.id, docker_api_types_image.RemoveOptions{})
	if err != nil {
		slog.Info("Could not remove temporary docker image", "err", err)
	}
}

// GetConfig Get the image config of this image
func (image ActiveImage) GetConfig() (config v1.Config, ok bool) {
	return image.Metadata.Config.Config, true
}

// BuildNewImage Build new image from a dockerfile;
// Caller is responsible to call image.TearDown() after usage
func BuildNewImage(dockerfilePath string) (image ActiveImage, err error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	slog.Info("Connecting to Docker Client using API version negotiaton", "client", os.Getenv("DOCKER_HOST"))
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return ActiveImage{}, err
	}

	slog.Debug("Tarring directory with Dockerfile", "path", dockerfilePath)
	tar, err := archive.Tar(filepath.Dir(dockerfilePath), archive.Gzip)
	if err != nil {
		return ActiveImage{}, err
	}
	defer tar.Close()

	buildOptions := types.ImageBuildOptions{
		Dockerfile:     filepath.Base(dockerfilePath),
		SuppressOutput: true,
	}

	slog.Info("Building Docker image", "path", dockerfilePath)
	imageBuildResponse, err := cli.ImageBuild(ctx, tar, buildOptions)
	if err != nil {
		return ActiveImage{}, err
	}
	defer imageBuildResponse.Body.Close()

	responseBytes, err := io.ReadAll(imageBuildResponse.Body)
	if err != nil {
		return ActiveImage{}, err
	}

	var responseStruct struct {
		DigestID string `json:"stream"`
	}

	if strings.Contains(string(responseBytes), "You have reached your pull rate limit.") {
		return ActiveImage{}, errors.New("failed to build image because pull rate limit is reached")
	}

	err = json.Unmarshal(responseBytes, &responseStruct)
	if err != nil {
		return ActiveImage{}, err
	}

	imageID := getImgIDWithoutDigest(responseStruct.DigestID)

	slog.Info("Docker image built successfully! ImageID", "id", imageID)

	stereoscopeImage, err := stereoscope.GetImage(ctx, imageID)
	if err != nil {
		if strings.Contains(err.Error(), "unable to save image tar: Error response from daemon: empty export - not implemented") {
			return ActiveImage{}, fmt.Errorf("provider: failed to export docker image since it is empty, this is a weird docker implementation and you should not pass empty images.\nFull Trace:\n%w", err)
		}
		return ActiveImage{}, err
	}

	return ActiveImage{
		stereoscopeImage,
		imageID,
		cli,
	}, err
}

// GetPrebuiltImage Parses a DockerImage from an identifier, possibly pulling it from a registry;
// Caller is responsible to call image.TearDown() after usage
func GetPrebuiltImage(name string) (image ActiveImage, err error) {
	slog.Info("Getting prebuilt image", "image", name)
	// context for network requests
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lctx, err := logrus.New(logrus.Config{
		EnableConsole: true,
		Level:         logger.TraceLevel,
	})
	if err != nil {
		return ActiveImage{}, err
	}
	stereoscope.SetLogger(lctx)

	stereoscopeImage, err := stereoscope.GetImage(ctx, name)
	if err != nil {
		return ActiveImage{}, err
	}

	imageID := getImgIDWithoutDigest(stereoscopeImage.Metadata.ID)

	slog.Info("Successfully acquired image", "image", name, "id", imageID)

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return ActiveImage{}, err
	}

	return ActiveImage{
		stereoscopeImage,
		imageID,
		cli,
	}, err
}

// GetSquashedFilesystem Get a squashed filesystem at top layer
func GetSquashedFilesystem(image ActiveImage) filesystem.Filesystem {
	return GetSquashedFilesystemAtIndex(image, len(image.Layers)-1)
}

// GetSquashedFilesystemAtIndex Get a squashed filesystem at layer with index
func GetSquashedFilesystemAtIndex(image ActiveImage, index int) filesystem.Filesystem {
	return Layer{
		Layer: image.Layers[index],
		index: index,
		image: &image,
	}
}

func getImgIDWithoutDigest(in string) string {
	imageID := strings.Split(in, ":")[1]
	return strings.TrimSpace(imageID)
}
