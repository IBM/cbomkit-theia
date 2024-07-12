package plugins

import (
	"ibm/container-image-cryptography-scanner/provider/filesystem"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type PluginType int

/* A list of possible plugin types

Important: order these in the way you want to run the plugins;
e.g. here the plugins are running in this order: PluginTypeAppend -> PluginTypeVerify -> PluginTypeOther 
*/
const (
	PluginTypeAppend PluginType = iota + 1
	PluginTypeVerify
	PluginTypeOther
)

// Interface to be implemented by all plugins
type Plugin interface {
	GetName() string                                                                            // return a name for the plugin
	GetType() PluginType                                                                        // return the plugin type
	UpdateComponents(components []cdx.Component) (updatedComponents []cdx.Component, err error) // Update all BOM components using found files
}

// This PluginConstructor function should be exposed by all plugin packages
type PluginConstructor func(filesystem filesystem.Filesystem) (Plugin, error)
