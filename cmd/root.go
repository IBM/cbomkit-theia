package cmd

import (
	"fmt"
	"ibm/container-image-cryptography-scanner/cmd/image"
	"ibm/container-image-cryptography-scanner/scanner"
	"ibm/container-image-cryptography-scanner/scanner/plugins"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var bomFilePath string
var bomSchemaPath string
var activatedPlugins []string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cics",
	Short: "Container Cryptography Scanner (CICS) verifies a given CBOM based on the given image or directory",
	Long: `
 ██████ ██  ██████ ███████ 
██      ██ ██      ██      
██      ██ ██      ███████ 
██      ██ ██           ██ 
 ██████ ██  ██████ ███████ by IBM Research

Container Image Cryptography Scanner (CICS) 
verifies a given CBOM based on the given image or directory

The input is analyzed for any configurations limiting 
the usage of cryptography. Using these findings, 
the given CBOM is updated and verified. Additionally, 
CICS adds new cryptographic assets to the CBOM. 

Supported image/filesystem sources:
- local directory 
- local application with dockerfile (ready to be build)
- local docker image from docker daemon
- local docker image as TAR archive
- local OCI image as directory
- local OCI image as TAR archive
- OCI image from OCI registry
- docker image from dockerhub registry
- image from singularity

Supported BOM formats (input & output):
- CycloneDXv1.6

Examples:
cics dir my/cool/directory --bom my/bom.json
cics image get nginx --bom my/bom.json
cics image build my/Dockerfile --bom my/bom.json`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(image.ImageCmd)
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cics.yaml)")

	rootCmd.PersistentFlags().StringVarP(&bomFilePath, "bom", "b", "", "BOM file to verify using the given data")
	viper.BindPFlag("bom", rootCmd.PersistentFlags().Lookup("bom"))
	rootCmd.MarkPersistentFlagFilename("bom", ".json")

	rootCmd.PersistentFlags().StringVar(&bomSchemaPath, "schema", filepath.Join("provider", "cyclonedx", "bom-1.6.schema.json"), "BOM schema to validate the given BOM")
	viper.BindPFlag("schema", rootCmd.PersistentFlags().Lookup("schema"))
	rootCmd.MarkPersistentFlagFilename("schema", ".json")

	allPluginNames := make([]string, len(scanner.GetAllPluginConstructors()))

	i := 0
	for k := range scanner.GetAllPluginConstructors() {
		allPluginNames[i] = k
		i++
	}

	rootCmd.PersistentFlags().StringSliceVarP(&activatedPlugins, "plugins", "p", allPluginNames, "list of plugins to use")
	viper.BindPFlag("plugins", rootCmd.PersistentFlags().Lookup("plugins"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".cics" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".cics")
	}

	viper.BindPFlag("docker_host", image.ImageCmd.PersistentFlags().Lookup("docker_host"))
	viper.SetDefault("docker_host", "unix:///var/run/docker.sock")

	viper.AutomaticEnv() // read in environment variables that match

	err := viper.ReadInConfig()
	if err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}

	if !viper.IsSet("bom") {
		rootCmd.MarkPersistentFlagRequired("bom")
	}

	pluginConstructors := make([]plugins.PluginConstructor, 0, len(viper.GetStringSlice("plugins")))
	for _, name := range viper.GetStringSlice("plugins") {
		constructor, ok := scanner.GetAllPluginConstructors()[name]
		if !ok {
			// Error
			panic(fmt.Sprintf("%v is not a valid plugin name!", name))
		} else {
			pluginConstructors = append(pluginConstructors, constructor)
		}
	}

	viper.Set("pluginConstructors", pluginConstructors)
}
