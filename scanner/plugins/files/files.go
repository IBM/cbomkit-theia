package files

import (
	"ibm/container_cryptography_scanner/provider/filesystem"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type FilePlugin struct {
}

func (filePlugin *FilePlugin) GetName() string {
	return "File Scanning Plugin"
}

func (filePlugin *FilePlugin) ParseRelevantFilesFromFilesystem(filesystem filesystem.Filesystem) error {
	return nil
}

func (filePlugin *FilePlugin) UpdateComponents(components []cdx.Component) (updatedComponents []cdx.Component, err error) {
	return components, nil
}
