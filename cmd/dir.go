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
	"io"
	"os"

	"github.com/IBM/cbomkit-theia/provider/filesystem"
	"github.com/IBM/cbomkit-theia/scanner"
	"github.com/IBM/cbomkit-theia/scanner/plugins"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/dig"
)

var dirCmd = &cobra.Command{
	Use:   "dir",
	Short: "Analyze cryptographic assets in a directory",
	Long: `Analyze cryptographic assets in a directory

Supported image/filesystem sources:
- local directory

Examples:
cbomkit-theia dir my/cool/directory
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

		if err := container.Provide(func() io.Writer {
			return os.Stdout
		}); err != nil {
			panic(err)
		}

		if err := container.Invoke(scanner.ReadFilesAndRunScan); err != nil {
			panic(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(dirCmd)
}
