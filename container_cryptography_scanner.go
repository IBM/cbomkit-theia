package main

import (
	"flag"
	"ibm/container_cryptography_scanner/provider/cyclonedx"
	"ibm/container_cryptography_scanner/provider/docker"
	"ibm/container_cryptography_scanner/scanner"
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
	bomPath := flag.String("bom", "", "path to v1.6 CycloneDX BOM file")
	filesystemPath := flag.String("filesystem", "", "path to filesystem to scan")
	dockerfilePath := flag.String("dockerfile", "", "path to the dockerfile")

	flag.Parse()

	if *bomPath == "" || *filesystemPath == "" || *dockerfilePath == "" {
		log.Fatal("Missing required command line parameter")
	}

	err := run(bomPath, filesystemPath, dockerfilePath, os.Stdout)
	if err != nil {
		panic(err)
	}
}

func run(bomPath *string, filesystemPath *string, dockerfilePath *string, target *os.File) error {
	schemaPath := filepath.Join("provider", "cyclonedx", "bom-1.6.schema.json")
	bom, err := cyclonedx.ParseBOM(*bomPath, schemaPath)
	if err != nil {
		return err
	}

	// Test Scannable Image
	scannableImage := docker.ScannableImage{
		Filesystem: docker.Filesystem{
			Path: *filesystemPath,
		},
		DockerfilePath: *dockerfilePath,
	}
	scanner2 := scanner.NewScanner(scannableImage)
	newBom, err := scanner2.Scan(*bom)
	if err != nil {
		return err
	}

	log.Default().Println("FINISHED SCANNING")

	err = cyclonedx.WriteBOM(&newBom, target)
	if err != nil {
		return nil
	}

	return nil
}
