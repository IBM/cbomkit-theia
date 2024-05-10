package main

import (
	"ibm/container_cryptography_scanner/provider/cyclonedx"
	"ibm/container_cryptography_scanner/scanner"
	"ibm/container_cryptography_scanner/provider/docker"
	"log"
	"os"
	"path/filepath"
)

func Check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	bomPath := filepath.Join("provider", "cyclonedx", "testfiles", "algorithm.json")
	schemaPath := filepath.Join("provider", "cyclonedx", "bom-1.6.schema.json")
	bom, err := cyclonedx.ParseBOM(bomPath, schemaPath)
	Check(err)

	// Java Testing
	configPath := filepath.Join("testdata", "1", "filesystem")
	dockerfilePath := filepath.Join("testdata", "1", "image", "policy.Dockerfile")

	// Test Scannable Image
	scannableImage := docker.ScannableImage {
		Filesystem: docker.Filesystem{
			Path: configPath,
		},
		DockerfilePath: dockerfilePath,
	}
	scanner2 := scanner.NewScanner(scannableImage)
	newBom := scanner2.Scan(*bom)

	log.Default().Println("FINISHED SCANNING")
	err = cyclonedx.WriteBOM(&newBom, os.Stdout)
	Check(err)
}
