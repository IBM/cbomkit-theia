package image

import (
	"ibm/container_cryptography_scanner/provider/docker"
	"ibm/container_cryptography_scanner/scanner"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var dockerHost string

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
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		os.Setenv("DOCKER_HOST", viper.GetString("docker_host"))
	},
}

func prepareImageAndRun(image docker.Image, err error) {
	if err != nil {
		panic(err)
	}
	defer image.TearDown()

	fs := docker.GetSquashedFilesystem(image)
	bom := viper.GetString("bom")
	schema := viper.GetString("schema")
	scanner.CreateAndRunScan(fs, os.Stdout, bom, schema)
}

func init() {
	ImageCmd.AddCommand(buildCmd)
	ImageCmd.AddCommand(getCmd)

	ImageCmd.PersistentFlags().StringVar(&dockerHost, "docker_host", "", "docker host to use for interacting with images; only set if DOCKER_HOST environment variable is not set; Default: unix:///var/run/docker.sock; Priority: Flag > ENV > Config File > Default")
}
