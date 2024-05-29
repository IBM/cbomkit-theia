package config

import (
	"ibm/container_cryptography_scanner/provider/filesystem"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type ConfigPlugin interface {
	GetName() string
	ParseConfigsFromFilesystem(filesystem filesystem.Filesystem) error
	UpdateComponents(components []cdx.Component) (updatedComponents []cdx.Component, err error)
}
