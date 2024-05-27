package docker

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"ibm/container_cryptography_scanner/provider/filesystem"

	"github.com/anchore/go-logger"
	"github.com/anchore/go-logger/adapter/logrus"
	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

type Image struct {
	*image.Image
	dockerfilePath string // This is empty if no Dockerfile is present
	tags []string
}

func (image Image) GetDockerfilePath() (path string, ok bool) {
	if image.dockerfilePath == "" {
		return "", false
	} else {
		return image.dockerfilePath, true
	}
}

func BuildNewImage(dockerfilePath string) (image Image, err error) {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return Image{}, err
	}

	dockerBuildContext, err := os.Open(dockerfilePath)
	if err != nil {
		return Image{}, err
	}
	defer dockerBuildContext.Close()

	buildOptions := types.ImageBuildOptions{
		Dockerfile: filepath.Base(dockerfilePath),
		Tags:       []string{"your_image_name:tag"}, // TODO from here
	}

	imageBuildResponse, err := cli.ImageBuild(ctx, dockerBuildContext, buildOptions)
	if err != nil {
		panic(err)
	}
	defer imageBuildResponse.Body.Close()

	_, err = io.Copy(os.Stdout, imageBuildResponse.Body)
	if err != nil {
		panic(err)
	}

	fmt.Println("Docker image built successfully!")
}

// Parses a DockerImage from an identifier, possibly pulling it from a registry
// Caller is responsible to call image.Cleanup() after usage
func GetPrebuiltImage(name string) (image Image, err error) {
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

	stereoscopeImage, err := stereoscope.GetImage(ctx, os.Args[1])
	return Image{
		stereoscopeImage,
		"",
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
