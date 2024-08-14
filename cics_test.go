package main

import (
	"os"
	"path/filepath"
	"testing"

	"ibm/container-image-cryptography-scanner/provider/cyclonedx"
	"ibm/container-image-cryptography-scanner/provider/docker"
	"ibm/container-image-cryptography-scanner/provider/filesystem"
	"ibm/container-image-cryptography-scanner/scanner"
	"ibm/container-image-cryptography-scanner/scanner/compare"

	"github.com/stretchr/testify/assert"
	"go.uber.org/dig"
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
}

func TestScan(t *testing.T) {
	schemaPath := filepath.Join("provider", "cyclonedx", "bom-1.6.schema.json")

	for _, test := range tests {
		t.Run(test.in+", BOM: "+test.in, func(t *testing.T) {
			tempTarget, err := os.CreateTemp("", "TestParseBOM")
			if err != nil {
				panic(err)
			}
			defer os.Remove(tempTarget.Name())

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

			if err := container.Provide(func() *os.File {
				return tempTarget
			}); err != nil {
				panic(err)
			}

			for _, pluginConstructor := range scanner.GetAllPluginConstructors() {
				if err = container.Provide(pluginConstructor, dig.Group("plugins")); err != nil {
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
				runErr = container.Invoke(scanner.CreateAndRunScan)
			case testTypeImageGet:
				image, err := docker.GetPrebuiltImage(test.additionalInfo)
				assert.NoError(t, err)
				defer image.TearDown()
				err = container.Provide(func() filesystem.Filesystem {
					return docker.GetSquashedFilesystem(image)
				})
				assert.NoError(t, err)
				runErr = container.Invoke(scanner.CreateAndRunScan)
			case testTypeDir:
				err := container.Provide(func() filesystem.Filesystem {
					return filesystem.NewPlainFilesystem(filepath.Join(testfileFolder, test.in, dirExtension))
				})
				assert.NoError(t, err)
				runErr = container.Invoke(scanner.CreateAndRunScan)
			}

			if test.err {
				assert.Error(t, runErr, "scan did not fail although it should")
			} else {
				assert.NoError(t, runErr, "scan did fail although it should not")
			}

			bomTrue, err := cyclonedx.ParseBOM(filepath.Join(testfileFolder, test.in, outputExtension), schemaPath)
			assert.NoError(t, err)
			bomCurrent, err := cyclonedx.ParseBOM(tempTarget.Name(), schemaPath)
			assert.NoError(t, err)

			assert.True(t, compare.EqualBOMWithoutRefs(*bomTrue, *bomCurrent))
		})
	}
}
