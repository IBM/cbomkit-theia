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
