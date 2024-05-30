package javasecurity

import (
	"ibm/container_cryptography_scanner/provider/filesystem"
	"log"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Represents the java security plugin in a specific scanning context
// Implements the config/ConfigPlugin interface
type JavaSecurityPlugin struct {
	security       JavaSecurity
	filesystem filesystem.Filesystem
}

// Get the name of the plugin for debugging purposes
func (javaSecurityPlugin *JavaSecurityPlugin) GetName() string {
	return "JavaSecurity Policy File"
}

// Parses all relevant information from the filesystem and creates underlying data structure for evaluation
func (javaSecurityPlugin *JavaSecurityPlugin) ParseConfigsFromFilesystem(filesystem filesystem.Filesystem) (err error) {
	javaSecurityPlugin.filesystem = filesystem

	err = filesystem.WalkDir(javaSecurityPlugin.configWalkDirFunc)
	if err != nil {
		return err
	}

	err = javaSecurityPlugin.checkConfig()
	if err != nil {
		return err
	}

	err = javaSecurityPlugin.security.extractTLSRules()
	if err != nil {
		return err
	}

	return err
}

// High-level function to update a list of components (e.g. remove components and add new ones)
func (javaSecurityPlugin *JavaSecurityPlugin) UpdateComponents(components []cdx.Component) (updatedComponents []cdx.Component, err error) {
	for _, component := range components {
		if component.Type == cdx.ComponentTypeCryptographicAsset && component.CryptoProperties != nil {
			javaSecurityPlugin.security.createCryptoComponentBOMRefMap(components)
			updatedComponent, err := javaSecurityPlugin.updateComponent(component)

			if err != nil {
				return nil, err
			}

			if updatedComponent == nil {
				continue
			} else {
				updatedComponents = append(updatedComponents, *updatedComponent)
			}
		}
	}
	return updatedComponents, err
}

// Assesses if the component is from a source affected by this type of config (e.g. a java file)
// Require "Evidence" and "Occurrences" to be present in the BOM
func (javaSecurityPlugin *JavaSecurityPlugin) isComponentAffectedByConfig(component cdx.Component) bool {
	if component.Evidence == nil || component.Evidence.Occurrences == nil { // If there is no evidence telling us that whether this component comes from a java file, we cannot assess it
		return false
	}

	for _, occurrence := range *component.Evidence.Occurrences {
		if filepath.Ext(occurrence.Location) == ".java" {
			return true
		}
	}

	// TODO: Check if security property were changed dynamically via System.setProperty

	return false
}

// Update a single component
// Returns nil if component is not allowed
func (javaSecurityPlugin *JavaSecurityPlugin) updateComponent(component cdx.Component) (updatedComponent *cdx.Component, err error) {

	if !javaSecurityPlugin.isComponentAffectedByConfig(component) {
		return &component, nil
	}

	log.Default().Printf("Detected %v", component.CryptoProperties.AssetType)

	switch component.CryptoProperties.AssetType {
	case cdx.CryptoAssetTypeProtocol:
		return javaSecurityPlugin.security.updateProtocolComponent(component)
	default:
		return &component, nil
	}
}
