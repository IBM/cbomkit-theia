package main

import (
	"ibm/container_cryptography_scanner/provider/cyclonedx"
	"ibm/container_cryptography_scanner/scanner"
)

func Check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	scanner.Scan("./scanner/openssl/testdata/openssl.cnf")
	cyclonedx.ParseCBOM("provider/cyclonedx/testfiles/algorithm.json")
}
