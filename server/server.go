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

package server

import (
	"bytes"
	"ibm/container-image-cryptography-scanner/provider/docker"
	"ibm/container-image-cryptography-scanner/provider/filesystem"
	"ibm/container-image-cryptography-scanner/scanner"
	"ibm/container-image-cryptography-scanner/scanner/plugins"
	"io"
	"net/http"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gin-gonic/gin"
	"go.uber.org/dig"
)

type imageGetRequest struct {
	Image   string   `json:"image" binding:"required"`
	Plugins []string `json:"plugins"`
	Bom     *cdx.BOM `json:"bom"`
}

func Serve() {
	r := gin.Default()
	r.GET("/v1/image/get", func(c *gin.Context) {
		request := imageGetRequest{
			Plugins: scanner.GetAllPluginNames(),
			Bom:     scanner.NewBOMWithMetadata(),
		}
		if err := c.ShouldBindBodyWithJSON(&request); err != nil {
			returnError(c, err)
			return
		} else {
			image, err := docker.GetPrebuiltImage(request.Image)
			if err != nil {
				returnError(c, err)
				return
			}
			defer image.TearDown()

			container := dig.New()

			if err = container.Provide(func() filesystem.Filesystem {
				return docker.GetSquashedFilesystem(image)
			}); err != nil {
				returnError(c, err)
				return
			}

			if err = container.Provide(func() *cdx.BOM {
				return request.Bom
			}); err != nil {
				returnError(c, err)
				return
			}

			output := new(bytes.Buffer)

			if err = container.Provide(func() io.Writer {
				return output
			}); err != nil {
				returnError(c, err)
				return
			}

			if err = container.Provide(func() ([]plugins.PluginConstructor, error) {
				return scanner.GetPluginConstructorsFromNames(request.Plugins)
			}); err != nil {
				returnError(c, err)
				return
			}

			if err = container.Provide(func(input []plugins.PluginConstructor) ([]plugins.Plugin, error) {
				plugins := make([]plugins.Plugin, len(input))
				for i, con := range input {
					plugins[i], err = con()
					if err != nil {
						return plugins, err
					}
				}
				return plugins, nil
			}); err != nil {
				returnError(c, err)
				return
			}

			if err = container.Invoke(scanner.RunScan); err != nil {
				returnError(c, err)
				return
			}

			c.DataFromReader(http.StatusOK, int64(len(output.Bytes())), "application/vnd.cyclonedx+json; version=1.6", output, map[string]string{})
		}
	})
	r.Run("localhost:8080") // listen and serve on 0.0.0.0:8080
}

func returnError(c *gin.Context, err error) {
	c.JSON(http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
}
