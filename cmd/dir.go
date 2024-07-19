package cmd

import (
	"ibm/container-image-cryptography-scanner/provider/filesystem"
	"ibm/container-image-cryptography-scanner/scanner"
	"ibm/container-image-cryptography-scanner/scanner/plugins"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/dig"
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
		container := dig.New()

		if err := container.Provide(func() filesystem.Filesystem {
			return filesystem.NewPlainFilesystem(args[0])
		}); err != nil {
			panic(err)
		}

		if err := container.Provide(func() string {
			return bomFilePath
		}, dig.Name("bomFilePath")); err != nil {
			panic(err)
		}

		if err := container.Provide(func() string {
			return bomSchemaPath
		}, dig.Name("bomSchemaPath")); err != nil {
			panic(err)
		}

		pluginConstructors, ok := viper.Get("pluginConstructors").([]plugins.PluginConstructor)

		if !ok {
			panic("Could not get pluginConstructors from Viper! This should not happen.")
		}

		for _, pluginConstructor := range pluginConstructors {
			if err := container.Provide(pluginConstructor, dig.Group("plugins")); err != nil {
				panic(err)
			}
		}

		if err := container.Provide(func() *os.File {
			return os.Stdout
		}); err != nil {
			panic(err)
		}

		if err := container.Invoke(scanner.CreateAndRunScan); err != nil {
			panic(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(dirCmd)
}
