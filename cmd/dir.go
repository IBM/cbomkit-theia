package cmd

import (
	"ibm/container-image-cryptography-scanner/provider/filesystem"
	"ibm/container-image-cryptography-scanner/scanner"
	"os"

	"github.com/spf13/cobra"
)

var dirCmd = &cobra.Command{
	Use:   "dir",
	Short: "Verify CBOM using a directory",
	Long: `Verify CBOM using a directory

- Verifies the CBOM assuming that the given directory is the filesystem the application runs in
- Provides the most value if directory contains the whole Linux filesystem tree that the application runs in

Supported image/filesystem sources:
- local directory

Examples:
cics dir my/cool/directory --bom my/bom.json

`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fs := filesystem.NewPlainFilesystem(args[0])
		scanner.CreateAndRunScan(fs, os.Stdout, bomFilePath, bomSchemaPath)
	},
}

func init() {
	rootCmd.AddCommand(dirCmd)
}
