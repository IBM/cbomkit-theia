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

package main

import (
	"bytes"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"ibm/container-image-cryptography-scanner/provider/cyclonedx"
	"ibm/container-image-cryptography-scanner/provider/docker"
	"ibm/container-image-cryptography-scanner/provider/filesystem"
	"ibm/container-image-cryptography-scanner/scanner"
	"ibm/container-image-cryptography-scanner/scanner/hash"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"go.uber.org/dig"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

var testfileFolder string = "./testdata"
var outputExtension string = "/out/bom.json"
var bomFolderExtension string = "/in/bom.json"
var dockerfileExtension string = "/image/Dockerfile"
var dirExtension string = "/dir"

type testType int

const (
	testTypeDir testType = iota + 1
	testTypeImageBuild
	testTypeImageGet
)

var tests = []struct {
	testType       testType
	additionalInfo string
	in             string
	err            bool
}{
	{testTypeImageBuild, "", "/0_empty", false},
	{testTypeImageGet, "busybox", "/0_empty", false},
	{testTypeImageBuild, "", "/1_exclude_single_algorithm", false},
	{testTypeImageBuild, "", "/2_tomcat", false},
	{testTypeImageBuild, "", "/3_certificates", false},
	{testTypeDir, "", "/4_unknown_keySize", false},
	{testTypeDir, "", "/5_single_certificate", false},
	{testTypeDir, "", "/6_malformed_java_security", false},
	{testTypeDir, "", "/7_private_key", false},
	{testTypeDir, "", "/8_secrets", false},
}

func TestScan(t *testing.T) {
	schemaPath := filepath.Join("provider", "cyclonedx", "bom-1.6.schema.json")

	for _, test := range tests {
		t.Run(test.in+", BOM: "+test.in, func(t *testing.T) {
			tempTarget := new(bytes.Buffer)

			var runErr error

			container := dig.New()

			if err := container.Provide(func() string {
				return testfileFolder + test.in + bomFolderExtension
			}, dig.Name("bomFilePath")); err != nil {
				panic(err)
			}

			if err := container.Provide(func() string {
				return schemaPath
			}, dig.Name("bomSchemaPath")); err != nil {
				panic(err)
			}

			if err := container.Provide(func() io.Writer {
				return tempTarget
			}); err != nil {
				panic(err)
			}

			for _, pluginConstructor := range scanner.GetAllPluginConstructors() {
				if err := container.Provide(pluginConstructor, dig.Group("plugins")); err != nil {
					panic(err)
				}
			}

			switch test.testType {
			case testTypeImageBuild:
				dockerfilePath := filepath.Join(testfileFolder, test.in, dockerfileExtension)
				image, err := docker.BuildNewImage(dockerfilePath)
				assert.NoError(t, err)
				defer image.TearDown()
				err = container.Provide(func() filesystem.Filesystem {
					return docker.GetSquashedFilesystem(image)
				})
				assert.NoError(t, err)
				runErr = container.Invoke(scanner.ReadFilesAndRunScan)
			case testTypeImageGet:
				image, err := docker.GetPrebuiltImage(test.additionalInfo)
				assert.NoError(t, err)
				defer image.TearDown()
				err = container.Provide(func() filesystem.Filesystem {
					return docker.GetSquashedFilesystem(image)
				})
				assert.NoError(t, err)
				runErr = container.Invoke(scanner.ReadFilesAndRunScan)
			case testTypeDir:
				err := container.Provide(func() filesystem.Filesystem {
					return filesystem.NewPlainFilesystem(filepath.Join(testfileFolder, test.in, dirExtension))
				})
				assert.NoError(t, err)
				runErr = container.Invoke(scanner.ReadFilesAndRunScan)
			}

			if test.err {
				assert.Error(t, runErr, "scan did not fail although it should")
			} else {
				assert.NoError(t, runErr, "scan did fail although it should not")
			}

			bomReaderTrue, _ := os.Open(filepath.Join(testfileFolder, test.in, outputExtension))
			schemaReader, _ := os.Open(schemaPath)
			bomTrue, err := cyclonedx.ParseBOM(bomReaderTrue, schemaReader)
			assert.NoError(t, err)
			bomCurrent, err := cyclonedx.ParseBOM(tempTarget, schemaReader)
			assert.NoError(t, err)

			assert.Empty(t, cmp.Diff(*bomTrue, *bomCurrent,
				cmpopts.SortSlices(func(a cdx.Service, b cdx.Service) bool {
					return a.Name < b.Name
				}),
				cmpopts.SortSlices(func(a cdx.Component, b cdx.Component) bool {
					aHash := hash.HashCDXComponentWithoutRefs(a)
					bHash := hash.HashCDXComponentWithoutRefs(b)
					return hex.EncodeToString(aHash[:]) < hex.EncodeToString(bHash[:])
				}),
				cmpopts.SortSlices(func(a cdx.EvidenceOccurrence, b cdx.EvidenceOccurrence) bool {
					if a.Location != b.Location {
						return a.Location < b.Location
					} else {
						return *a.Line < *b.Line
					}
				}),
				cmpopts.IgnoreTypes(cdx.Dependency{}),
				cmpopts.IgnoreFields(cdx.Component{},
					"BOMRef",
					"CryptoProperties.CertificateProperties.SignatureAlgorithmRef",
					"CryptoProperties.CertificateProperties.SubjectPublicKeyRef",
					"CryptoProperties.RelatedCryptoMaterialProperties.AlgorithmRef",
					"CryptoProperties.RelatedCryptoMaterialProperties.SecuredBy.AlgorithmRef",
					"CryptoProperties.ProtocolProperties.CryptoRefArray"),
			))
		})
	}
}
