package scanner

import (
	"ibm/container_cryptography_scanner/scanner/config"
	"ibm/container_cryptography_scanner/scanner/javasecurity"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func Check(e error) {
	if e != nil {
		panic(e)
	}
}

type scanner struct {
	configPlugins []config.ConfigPlugin
	directoryPath string
}

func (scanner *scanner) findConfigFiles() {
	for _, plugin := range scanner.configPlugins {
		err := plugin.ParseConfigsFromFilesystem(scanner.directoryPath)
		if err != nil {
			panic(err)
		}
	}
}

func (scanner *scanner) Scan(bom cdx.BOM) cdx.BOM {
	scanner.findConfigFiles()

	for _, plugin := range scanner.configPlugins {
		err := plugin.UpdateComponents(bom.Components)
		if err != nil {
			panic(err)
		}
	}

	return bom
}

func NewScanner(directoryPath string) scanner {
	scanner := scanner{}
	scanner.configPlugins = []config.ConfigPlugin{
		&javasecurity.JavaSecurityPlugin{},
	}
	scanner.directoryPath = directoryPath

	return scanner
}
