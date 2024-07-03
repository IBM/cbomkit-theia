package image

import (
	"ibm/container-image-cryptography-scanner/provider/docker"

	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Verify CBOM using a prebuilt container image",
	Long: `Verify CBOM using a prebuilt container image

Supported image sources:
- local docker image from docker daemon
- local docker image as TAR archive
- local OCI image as directory
- local OCI image as TAR archive
- OCI image from OCI registry
- docker image from dockerhub registry
- image from singularity

Examples:
cics image get nginx --bom my/bom.json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		image, err := docker.GetPrebuiltImage(args[0])
		prepareImageAndRun(image, err)
	},
}

func init() {
}
