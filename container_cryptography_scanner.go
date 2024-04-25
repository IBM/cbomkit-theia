package main

import (
	"ibm/container_cryptography_scanner/provider/cyclonedx"
	"ibm/container_cryptography_scanner/scanner"
	"log"
	"os"
)

func Check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	bom := cyclonedx.ParseBOM("provider/cyclonedx/testfiles/algorithm.json")

	scanner := scanner.NewScanner("./scanner/openssl/testdata")
	newBom := scanner.Scan(*bom)

	log.Default().Println("FINISHED SCANNING")
	cyclonedx.WriteCBOM(&newBom, os.Stdout)
}
