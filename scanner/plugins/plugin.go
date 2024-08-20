package plugins

import (
	"ibm/container-image-cryptography-scanner/provider/filesystem"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type PluginType int

/*
	A list of possible plugin types

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
	GetName() string                                        // return a name for the plugin
	GetType() PluginType                                    // return the plugin type
	UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error // Update BOM using found files
}

// This PluginConstructor function should be exposed by all plugin packages
type PluginConstructor func() (Plugin, error)

func PluginSliceToString(plugins []Plugin) string {
	builder := strings.Builder{}
	for i, plugin := range plugins {
		builder.WriteString(plugin.GetName())
		if i < len(plugins)-1 {
			builder.WriteString("; ")
		}
	}
	return builder.String()
}
