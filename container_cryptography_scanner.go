package main

import (
	"ibm/container_cryptography_scanner/provider/cyclonedx"
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
	bomPath := filepath.Join("provider", "cyclonedx", "testfiles", "algorithm.json")
	schemaPath := filepath.Join("provider", "cyclonedx", "bom-1.6.schema.json")
	bom, err := cyclonedx.ParseBOM(bomPath, schemaPath)
	Check(err)

	configPath := filepath.Join("scanner", "openssl", "testdata")
	scanner1 := scanner.NewScanner(configPath)
	newBom := scanner1.Scan(*bom)

	log.Default().Println("FINISHED SCANNING")
	err = cyclonedx.WriteBOM(&newBom, os.Stdout)
	Check(err)

	// Java Testing
	configPath = filepath.Join("scanner", "javasecurity", "testdata")
	scanner2 := scanner.NewScanner(configPath)
	newBom = scanner2.Scan(*bom)

	log.Default().Println("FINISHED SCANNING")
	err = cyclonedx.WriteBOM(&newBom, os.Stdout)
	Check(err)
}
