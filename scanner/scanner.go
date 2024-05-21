package scanner

import (
	"ibm/container_cryptography_scanner/scanner/config"
	"ibm/container_cryptography_scanner/scanner/javasecurity"
	"ibm/container_cryptography_scanner/scanner/openssl"
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

func (scanner *scanner) findConfigFiles() error {
	for _, plugin := range scanner.configPlugins {
		err := plugin.ParseConfigsFromFilesystem(scanner.scannableImage)
		if err != nil {
			return err
		}
	}
	return nil
}

func (scanner *scanner) Scan(bom cdx.BOM) (cdx.BOM, error) {
	scanner.findConfigFiles()
	newComponents := make([]cdx.Component, 0, len(*bom.Components))

	for _, plugin := range scanner.configPlugins {
		updatedConfigComponents, err := plugin.UpdateComponents(*bom.Components)
		newComponents = append(newComponents, updatedConfigComponents...)
		if err != nil {
			return bom, err
		}
	}
	bom.Components = &newComponents
	return bom, nil
}

func NewScanner(scannableImage docker.ScannableImage) scanner {
	scanner := scanner{}
	scanner.configPlugins = []config.ConfigPlugin{
		&openssl.OpenSSLPlugin{},
		&javasecurity.JavaSecurityPlugin{},
	}
	scanner.scannableImage = scannableImage

	return scanner
}
