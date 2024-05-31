package image

import (
	"ibm/container_cryptography_scanner/provider/docker"
	"ibm/container_cryptography_scanner/scanner"
	"os"

	"github.com/spf13/cobra"
)

// imageCmd represents the image command
var ImageCmd = &cobra.Command{
	Use:   "image",
	Short: "Verify CBOM using a container image",
	Long: `Verify CBOM using a container image

Supported image sources:
- local application with dockerfile (ready to be build)
- local docker image from docker daemon
- local docker image as TAR archive
- local OCI image as directory
- local OCI image as TAR archive
- OCI image from OCI registry
- docker image from dockerhub registry
- image from singularity`,
}

func prepareImageAndRun(image docker.Image, err error) {
	if err != nil {
		panic(err)
	}
	defer image.TearDown()

	fs := docker.GetSquashedFilesystem(image)
	bom, err := ImageCmd.Flags().GetString("bom")
	if err != nil {
		panic(err)
	}
	schema, err := ImageCmd.Flags().GetString("schema")
	if err != nil {
		panic(err)
	}
	scanner.CreateAndRunScan(fs, os.Stdout, bom, schema)
}

func init() {
	ImageCmd.AddCommand(buildCmd)
	ImageCmd.AddCommand(getCmd)
}
