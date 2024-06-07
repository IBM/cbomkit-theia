package config

import (
	"ibm/container_cryptography_scanner/provider/filesystem"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Interface to be implemented by all plugins
type ConfigPlugin interface {
	GetName() string // return a name for the plugin
	ParseConfigsFromFilesystem(filesystem filesystem.Filesystem) error // find all config files in the filesystem
	UpdateComponents(components []cdx.Component) (updatedComponents []cdx.Component, err error) // Update all BOM components using found configurations
}
