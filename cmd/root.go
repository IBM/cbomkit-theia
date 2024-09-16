// Copyright 2024 IBM
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"ibm/cbomkit-theia/cmd/image"
	"ibm/cbomkit-theia/scanner"
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
	Use:   "cbomkit-theia",
	Short: "CBOMkit-theia analyzes cryptographic assets in a container image or directory",
	Long: `
 ██████╗██████╗  ██████╗ ███╗   ███╗██╗  ██╗██╗████████╗████████╗██╗  ██╗███████╗██╗ █████╗ 
██╔════╝██╔══██╗██╔═══██╗████╗ ████║██║ ██╔╝██║╚══██╔══╝╚══██╔══╝██║  ██║██╔════╝██║██╔══██╗
██║     ██████╔╝██║   ██║██╔████╔██║█████╔╝ ██║   ██║█████╗██║   ███████║█████╗  ██║███████║
██║     ██╔══██╗██║   ██║██║╚██╔╝██║██╔═██╗ ██║   ██║╚════╝██║   ██╔══██║██╔══╝  ██║██╔══██║
╚██████╗██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██╗██║   ██║      ██║   ██║  ██║███████╗██║██║  ██║
 ╚═════╝╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═╝ by IBM Research

CBOMkit-theia analyzes cryptographic assets in a container image or directory.
It is part of cbomkit (https://github.com/IBM/cbomkit) by IBM Research.

--> Disclaimer: CBOMkit-theia does *not* perform source code scanning <--
--> Use https://github.com/IBM/sonar-cryptography for source code scanning <--

Features
- Find certificates in your image/directory
- Find keys in your image/directory
- Find secrets in your image/directory
- Verify the executability of cryptographic assets in a CBOM (requires --bom to be set)
- Output: Enriched CBOM to stdout/console

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
cbomkit-theia dir my/cool/directory
cbomkit-theia image get nginx
cbomkit-theia image build my/Dockerfile` + "\n\n" + getPluginExplanations(),
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

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cbomkit-theia.yaml)")

	rootCmd.PersistentFlags().StringVarP(&bomFilePath, "bom", "b", "", "BOM file to be verified and enriched")
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

		// Search config in home directory with name ".cbomkit-theia" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".cbomkit-theia")
	}

	viper.BindPFlag("docker_host", image.ImageCmd.PersistentFlags().Lookup("docker_host"))
	viper.SetDefault("docker_host", "unix:///var/run/docker.sock")

	viper.AutomaticEnv() // read in environment variables that match

	err := viper.ReadInConfig()
	if err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}

	pluginConstructors, err := scanner.GetPluginConstructorsFromNames(viper.GetStringSlice("plugins"))
	if err != nil {
		panic(err)
	}
	viper.Set("pluginConstructors", pluginConstructors)
}

func getPluginExplanations() string {
	out := "Plugin Explanations:\n"
	for name, constructor := range scanner.GetAllPluginConstructors() {
		p, err := constructor()
		if err != nil {
			panic(err)
		}
		out += fmt.Sprintf("> \"%v\": %v\n%v\n\n", name, p.GetName(), p.GetExplanation())
	}
	return out
}
