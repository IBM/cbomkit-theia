package main

import (
	"flag"
	"ibm/container_cryptography_scanner/provider/cyclonedx"
	"ibm/container_cryptography_scanner/provider/docker"
	"ibm/container_cryptography_scanner/provider/filesystem"
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
	imageName := flag.String("image", "", "identifier for image")

	flag.Parse()

	if *bomPath == "" {
		log.Fatal("Missing bom command line parameter")
	}

	inputs := []string{*filesystemPath, *dockerfilePath, *imageName}
	var count int
	for _, input := range inputs {
		if input != "" {
			count++
		}
	}
	if count > 1 {
		log.Fatal("Multiple inputs specified. Only one is allowed.")
	}

	err := run(bomPath, filesystemPath, dockerfilePath, imageName, os.Stdout)
	if err != nil {
		panic(err)
	}
}

func run(bomPath *string, filesystemPath *string, dockerfilePath *string, imageName *string, target *os.File) error {
	schemaPath := filepath.Join("provider", "cyclonedx", "bom-1.6.schema.json")
	bom, err := cyclonedx.ParseBOM(*bomPath, schemaPath)
	if err != nil {
		return err
	}

	var fs filesystem.Filesystem
	if *filesystemPath != "" {
		fs = filesystem.NewPlainFilesystem(*filesystemPath)
	} else if *dockerfilePath != "" {
		image, err := docker.BuildNewImage(*dockerfilePath)
		if err != nil {
			return err
		}
		defer image.TearDown()
		fs = docker.GetSquashedFilesystem(image)
	} else if *imageName != "" {
		image, err := docker.GetPrebuiltImage(*imageName)
		if err != nil {
			return err
		}
		defer image.TearDown()
		fs = docker.GetSquashedFilesystem(image)
	}

	scanner := scanner.NewScanner(fs)
	newBom, err := scanner.Scan(*bom)
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
