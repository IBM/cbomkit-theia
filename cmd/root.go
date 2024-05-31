package cmd

import (
	"fmt"
	"ibm/container_cryptography_scanner/cmd/image"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var bomFilePath string
var bomSchemaPath string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cics",
	Short: "Container Cryptography Scanner (CICS) verifies a given CBOM based on the given image or directory",
	Long: `Container Image Cryptography Scanner (CICS) 
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
- CycloneDXv1.6`,
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

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cics.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	rootCmd.PersistentFlags().StringVarP(&bomFilePath, "bom", "b", "", "BOM file to verify using the given data")
	viper.BindPFlag("bom", rootCmd.PersistentFlags().Lookup("bom"))
	rootCmd.MarkPersistentFlagRequired("bom")
	rootCmd.MarkPersistentFlagFilename("bom", ".json")

	rootCmd.PersistentFlags().StringVar(&bomSchemaPath, "schema", filepath.Join("provider", "cyclonedx", "bom-1.6.schema.json"), "BOM schema to validate the given BOM")
	viper.BindPFlag("schema", rootCmd.PersistentFlags().Lookup("schema"))
	rootCmd.MarkPersistentFlagFilename("schema", ".json")
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

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
