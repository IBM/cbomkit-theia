package scanner

import (
	"ibm/container_cryptography_scanner/provider/filesystem"
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
	filesystem    filesystem.Filesystem
}

func (scanner *scanner) findConfigFiles() error {
	for _, plugin := range scanner.configPlugins {
		err := plugin.ParseConfigsFromFilesystem(scanner.filesystem)
		if err != nil {
			return err
		}
	}
	return nil
}

func (scanner *scanner) Scan(bom cdx.BOM) (cdx.BOM, error) {
	err := scanner.findConfigFiles()
	if err != nil {
		return cdx.BOM{}, err
	}
	
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

func NewScanner(filesystem filesystem.Filesystem) scanner {
	scanner := scanner{}
	scanner.configPlugins = []config.ConfigPlugin{
		&javasecurity.JavaSecurityPlugin{},
	}
	scanner.filesystem = filesystem

	return scanner
}
