package scanner

import (
	openssl_conf "ibm/container_cryptography_scanner/scanner/openssl"
	"os"
)

func Check(e error) {
	if e != nil {
		panic(e)
	}
}

func Scan(path string) {
	dat, err := os.ReadFile(path) // TODO: Make dynamic
	Check(err)

	openssl_conf.ParseOpensslConf(string(dat))
}
