package plugins

import (
	"ibm/container_cryptography_scanner/provider/filesystem"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Interface to be implemented by all plugins
type Plugin interface {
	GetName() string                                                                            // return a name for the plugin
	ParseRelevantFilesFromFilesystem(filesystem filesystem.Filesystem) error                    // find all relevant files in the filesystem
	UpdateComponents(components []cdx.Component) (updatedComponents []cdx.Component, err error) // Update all BOM components using found files
}