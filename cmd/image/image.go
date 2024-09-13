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

package image

import (
	"ibm/cbomkit-theia/provider/docker"
	"ibm/cbomkit-theia/provider/filesystem"
	"ibm/cbomkit-theia/scanner"
	"ibm/cbomkit-theia/scanner/plugins"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/dig"
)

var dockerHost string

var ImageCmd = &cobra.Command{
	Use:   "image",
	Short: "Analyze cryptographic assets in a container image",
	Long: `Analyze cryptographic assets in a container image

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

// This function basically extract all information that is still missing, such as the BOM and the schema and runs a scan on the images top layer
func prepareImageAndRun(image docker.ActiveImage, err error) {
	if err != nil {
		panic(err)
	}
	defer image.TearDown()

	container := dig.New()

	if err = container.Provide(func() filesystem.Filesystem {
		return docker.GetSquashedFilesystem(image)
	}); err != nil {
		panic(err)
	}

	if err = container.Provide(func() string {
		return viper.GetString("bom")
	}, dig.Name("bomFilePath")); err != nil {
		panic(err)
	}

	if err = container.Provide(func() string {
		return viper.GetString("schema")
	}, dig.Name("bomSchemaPath")); err != nil {
		panic(err)
	}

	if err = container.Provide(func() *os.File {
		return os.Stdout
	}); err != nil {
		panic(err)
	}

	pluginConstructors, ok := viper.Get("pluginConstructors").([]plugins.PluginConstructor)

	if !ok {
		panic("Could not get pluginConstructors from Viper! This should not happen.")
	}

	for _, pluginConstructor := range pluginConstructors {
		if err = container.Provide(pluginConstructor, dig.Group("plugins")); err != nil {
			panic(err)
		}
	}

	if err = container.Invoke(scanner.CreateAndRunScan); err != nil {
		panic(err)
	}
}

func init() {
	ImageCmd.AddCommand(buildCmd)
	ImageCmd.AddCommand(getCmd)

	ImageCmd.PersistentFlags().StringVar(&dockerHost, "docker_host", "", "docker host to use for interacting with images; only set if DOCKER_HOST environment variable is not set; Default: unix:///var/run/docker.sock; Priority: Flag > ENV > Config File > Default")
}
