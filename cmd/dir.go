package cmd

import (
	"ibm/container_cryptography_scanner/provider/filesystem"
	"ibm/container_cryptography_scanner/scanner"
	"os"

	"github.com/spf13/cobra"
)

var dirCmd = &cobra.Command{
	Use:   "dir",
	Short: "Verify CBOM using a directory",
	Long: `Verify CBOM using a directory

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
