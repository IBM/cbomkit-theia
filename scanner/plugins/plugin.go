package plugins

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"ibm/container-image-cryptography-scanner/provider/filesystem"
)

// Interface to be implemented by all plugins
type Plugin interface {
	GetName() string                                                                            // return a name for the plugin
	UpdateComponents(components []cdx.Component) (updatedComponents []cdx.Component, err error) // Update all BOM components using found files
}

type PluginConstructor func(filesystem filesystem.Filesystem) (Plugin, error)