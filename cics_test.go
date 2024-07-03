package main

import (
	"os"
	"path/filepath"
	"testing"

	"ibm/container-image-cryptography-scanner/provider/docker"
	"ibm/container-image-cryptography-scanner/provider/filesystem"
	"ibm/container-image-cryptography-scanner/scanner"

	"github.com/stretchr/testify/assert"
)

var testfileFolder string = "./testdata"
var outputExtension string = "/out/bom.json"
var bomFolderExtension string = "/in/bom.json"
var dockerfileExtension string = "/image/Dockerfile"
var fsExtension string = "/fs"

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
	{testTypeImageBuild, "", "/1_exclude_single_algorithm", false},
	{testTypeImageGet, "busybox", "/0_empty", false},
	{testTypeImageBuild, "", "/2_tomcat", false},
}

func runImage(image docker.ActiveImage, target *os.File, bomFilePath string, bomSchemaPath string) error {
	fs := docker.GetSquashedFilesystem(image)
	return scanner.CreateAndRunScan(fs, target, bomFilePath, bomSchemaPath)
}

func TestScan(t *testing.T) {
	schemaPath := filepath.Join("provider", "cyclonedx", "bom-1.6.schema.json")

	for _, test := range tests {
		t.Run(test.in+", BOM: "+test.in, func(t *testing.T) {
			bomFolder := testfileFolder + test.in + bomFolderExtension

			tempTarget, err := os.CreateTemp("", "TestParseBOM")
			if err != nil {
				panic(err)
			}
			defer os.Remove(tempTarget.Name())

			var runErr error

			switch test.testType {
			case testTypeImageBuild:
				dockerfilePath := testfileFolder + test.in + dockerfileExtension
				image, err := docker.BuildNewImage(dockerfilePath)
				assert.NoError(t, err)
				defer image.TearDown()
				runErr = runImage(image, tempTarget, bomFolder, schemaPath)
			case testTypeImageGet:
				image, err := docker.GetPrebuiltImage(test.additionalInfo)
				assert.NoError(t, err)
				defer image.TearDown()
				runErr = runImage(image, tempTarget, bomFolder, schemaPath)
			case testTypeDir:
				fs := filesystem.NewPlainFilesystem(test.in)
				assert.NoError(t, err)
				runErr = scanner.CreateAndRunScan(fs, tempTarget, bomFolder, schemaPath)
			}

			if test.err {
				assert.Error(t, runErr, "scan did not fail although it should")
			} else {
				assert.NoError(t, runErr, "scan did fail although it should not")
			}

			output, err := os.ReadFile(tempTarget.Name())
			if err != nil {
				panic(err)
			}

			trueOutput, err := os.ReadFile(testfileFolder + test.in + outputExtension)
			if err != nil {
				panic(err)
			}

			assert.JSONEqf(t, string(trueOutput), string(output), "resulting JSONs do not equal")
		})
	}
}
