package scanner

import (
	"ibm/container_cryptography_scanner/scanner/config"
	"ibm/container_cryptography_scanner/scanner/javasecurity"
	"ibm/container_cryptography_scanner/provider/docker"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func Check(e error) {
	if e != nil {
		panic(e)
	}
}

type scanner struct {
	configPlugins []config.ConfigPlugin
	scannableImage docker.ScannableImage
}

func (scanner *scanner) findConfigFiles() {
	for _, plugin := range scanner.configPlugins {
		err := plugin.ParseConfigsFromFilesystem(scanner.scannableImage)
		if err != nil {
			panic(err)
		}
	}
}

func (scanner *scanner) Scan(bom cdx.BOM) cdx.BOM {
	scanner.findConfigFiles()
	newComponents := make([]cdx.Component, 0, len(*bom.Components))

	for _, plugin := range scanner.configPlugins {
		updatedConfigComponents, err := plugin.UpdateComponents(*bom.Components)
		newComponents = append(newComponents, updatedConfigComponents...)
		if err != nil {
			panic(err)
		}
	}
	bom.Components = &newComponents
	return bom
}

func NewScanner(scannableImage docker.ScannableImage) scanner {
	scanner := scanner{}
	scanner.configPlugins = []config.ConfigPlugin{
		&javasecurity.JavaSecurityPlugin{},
	}
	scanner.scannableImage = scannableImage

	return scanner
}
