package image

import (
	"ibm/container_cryptography_scanner/provider/docker"

	"github.com/spf13/cobra"
)

// dockerfileCmd represents the dockerfile command
var buildCmd = &cobra.Command{
	Use:   "build",
	Short: "Verify CBOM using a new container image",
	Long: `Build a new container and verify CBOM based on that

Supported image sources:
- local application with dockerfile (ready to be build)

Examples:
cics image build my/Dockerfile --bom my/bom.json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		image, err := docker.BuildNewImage(args[0])
		prepareImageAndRun(image, err)
	},
}

func init() {
}
