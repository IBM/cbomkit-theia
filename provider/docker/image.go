package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"

	"ibm/container_cryptography_scanner/provider/filesystem"

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

type Image struct {
	*image.Image
	id     string
	client *client.Client
}

func (image Image) TearDown() {
	log.Default().Printf("Removing Image: %v", image.id)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := image.Cleanup()
	if err != nil {
		panic(err)
	}

	_, err = image.client.ImageRemove(ctx, image.id, docker_api_types_image.RemoveOptions{})
	if err != nil {
		log.Default().Printf("Could not remove temporary docker image. Continuing. Error: %v", err)
	}
}

func (image Image) GetConfig() (config v1.Config, ok bool) {
	return image.Metadata.Config.Config, true
}

// Build new image from a dockerfile
// Caller is responsible to call image.TearDown() after usage
func BuildNewImage(dockerfilePath string) (image Image, err error) {
	log.Default().Printf("Building Docker image from %v", dockerfilePath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return Image{}, err
	}

	tar, err := archive.Tar(filepath.Dir(dockerfilePath), archive.Gzip)
	if err != nil {
		return Image{}, err
	}
	defer tar.Close()

	buildOptions := types.ImageBuildOptions{
		Dockerfile:     filepath.Base(dockerfilePath),
		SuppressOutput: true,
	}

	imageBuildResponse, err := cli.ImageBuild(ctx, tar, buildOptions)
	if err != nil {
		return Image{}, err
	}
	defer imageBuildResponse.Body.Close()

	responseBytes, err := io.ReadAll(imageBuildResponse.Body)
	if err != nil {
		return Image{}, err
	}

	var responseStruct struct {
		DigestID string `json:"stream"`
	}

	err = json.Unmarshal(responseBytes, &responseStruct)
	if err != nil {
		return Image{}, err
	}

	imageID := getImgIDWithoutDigest(responseStruct.DigestID)

	log.Default().Printf("Docker image built successfully! ImageID: %v", imageID)

	stereoscopeImage, err := stereoscope.GetImage(ctx, imageID) // TODO: add specific host here
	if err != nil {
		if strings.Contains(err.Error(), "unable to save image tar: Error response from daemon: empty export - not implemented") {
			return Image{}, fmt.Errorf("scanner: failed to export docker image since it is empty, this is a weird docker implementation and you should not pass empty images.\nFull Trace:\n%w", err)
		}
		return Image{}, err
	}

	return Image{
		stereoscopeImage,
		imageID,
		cli,
	}, err
}

// Parses a DockerImage from an identifier, possibly pulling it from a registry
// Caller is responsible to call image.TearDown() after usage
func GetPrebuiltImage(name string) (image Image, err error) {
	log.Default().Printf("Getting prebuilt image %v", name)
	// context for network requests
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lctx, err := logrus.New(logrus.Config{
		EnableConsole: true,
		Level:         logger.TraceLevel,
	})
	if err != nil {
		return Image{}, err
	}
	stereoscope.SetLogger(lctx)

	stereoscopeImage, err := stereoscope.GetImage(ctx, name)
	if err != nil {
		return Image{}, err
	}

	imageID := getImgIDWithoutDigest(stereoscopeImage.Metadata.ID)

	log.Default().Printf("Successfully acquired image %v with id %v", name, imageID)

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return Image{}, err
	}

	return Image{
		stereoscopeImage,
		imageID,
		cli,
	}, err
}

func GetSquashedFilesystem(image Image) filesystem.Filesystem {
	return GetSquashedFilesystemAtIndex(image, len(image.Layers)-1)
}

func GetSquashedFilesystemAtIndex(image Image, index int) filesystem.Filesystem {
	return Layer{
		index: index,
		image: image,
	}
}

func getImgIDWithoutDigest(in string) string {
	imageID := strings.Split(in, ":")[1]
	return strings.TrimSpace(imageID)
}
