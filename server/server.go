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
	"ibm/cbomkit-theia/provider/docker"
	"ibm/cbomkit-theia/provider/filesystem"
	"ibm/cbomkit-theia/scanner"
	"ibm/cbomkit-theia/scanner/plugins"
	"io"
	"net/http"

	"go.uber.org/dig"

	cdx "github.com/CycloneDX/cyclonedx-go"

	_ "ibm/cbomkit-theia/docs"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

//	@title			CBOMkit-theia
//	@version		1.0
//	@description	CBOMkit-theia analyzes cryptographic assets in a container image or directory.

//	@license.name	Apache 2.0
//	@license.url	http://www.apache.org/licenses/LICENSE-2.0.html

//	@host		localhost:8080
//	@BasePath	/api/v1

//	@accept		json
//	@produce	application/vnd.cyclonedx+json; version=1.6

type imageGetRequest struct {
	Image   string   `json:"image" binding:"required" example:"nginx"`
	Plugins []string `json:"plugins" example:"certificates"`
	Bom     *cdx.BOM `json:"bom"`
}

type errorResponse struct {
	Err string `json:"error"`
}

func Serve() {

	_ = cdx.BOM{SerialNumber: "urn:uuid:e6e36f08-21a0-4a53-bb4c-96e489e6a453"}

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.Use(cors.Default()) // Allow all origins
	r.SetTrustedProxies(nil)
	v1 := r.Group("/api/v1")
	{
		v1.POST("/image/get", imageGet)
	}
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	r.Run(":8080") // listen and serve on 0.0.0.0:8080
}

// imageGet godoc
//
//	@Summary	Generate CBOM from existing image
//	@Tags		image
//	@Accept		json
//
//	@Param		request	body	imageGetRequest	false	"Request body containing the image identifier, list of activated plugins and BOM."
//	@Produce	application/vnd.cyclonedx+json; version=1.6
//	@Success	200	{object}	cdx.BOM
//	@Failure	400	{object}	errorResponse
//	@Router		/image/get [post]
func imageGet(c *gin.Context) {
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
}

func returnError(c *gin.Context, err error) {
	c.JSON(http.StatusBadRequest, errorResponse{Err: err.Error()})
}
