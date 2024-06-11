package javasecurity

import (
	go_errors "errors"
	"fmt"
	"ibm/container_cryptography_scanner/provider/filesystem"
	scanner_errors "ibm/container_cryptography_scanner/scanner/errors"
	"log/slog"
	"path/filepath"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Represents the java security plugin in a specific scanning context
// Implements the config/ConfigPlugin interface
type JavaSecurityPlugin struct {
	security   JavaSecurity
	filesystem filesystem.Filesystem
}

// Get the name of the plugin for debugging purposes
func (javaSecurityPlugin *JavaSecurityPlugin) GetName() string {
	return "java.security Plugin"
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

	return nil
}

// High-level function to update a list of components (e.g. remove components and add new ones)
func (javaSecurityPlugin *JavaSecurityPlugin) UpdateComponents(components []cdx.Component) (updatedComponents []cdx.Component, err error) {
	javaSecurityPlugin.security.createCryptoComponentBOMRefMap(components)

	insufficientInformationErrors := []error{}
	additionalComponentsToBeRemoved := []cdx.BOMReference{}

	for _, component := range components {
		if component.Type == cdx.ComponentTypeCryptographicAsset {
			if component.CryptoProperties != nil {
				updatedComponent, toBeRemoved, err := javaSecurityPlugin.updateComponent(component)
				additionalComponentsToBeRemoved = append(additionalComponentsToBeRemoved, toBeRemoved...)

				if err != nil {
					if go_errors.Is(err, scanner_errors.ErrInsufficientInformation) {
						insufficientInformationErrors = append(insufficientInformationErrors, err)
					} else {
						return nil, fmt.Errorf("scanner java: error while updating component %v\n%w", component, err)
					}
				}

				if updatedComponent == nil { // Component is not allowed
					continue
				} else {
					updatedComponents = append(updatedComponents, *updatedComponent)
				}
			} else {
				slog.Info("Component is a crypto asset but has empty properties. Cannot evaluate that. Continuing.", "component", component.Name)
			}
		}
	}

	cleanedComponents := []cdx.Component{}

	for _, component := range updatedComponents {
		if !slices.Contains(additionalComponentsToBeRemoved, cdx.BOMReference(component.BOMRef)) {
			cleanedComponents = append(cleanedComponents, component)
		}	
	}

	if len(insufficientInformationErrors) > 0 {
		all := make([]string, len(insufficientInformationErrors))
		for _, e := range insufficientInformationErrors {
			if e != nil {
				all = append(all, e.Error())
			}
		}

		slog.Warn("Run finished with insufficient information errors", "errors", all)
	}

	return cleanedComponents, nil
}

// Assesses if the component is from a source affected by this type of config (e.g. a java file), requires "Evidence" and "Occurrences" to be present in the BOM
func (javaSecurityPlugin *JavaSecurityPlugin) isComponentAffectedByConfig(component cdx.Component) (bool, error) {
	if component.Evidence == nil || component.Evidence.Occurrences == nil { // If there is no evidence telling us that whether this component comes from a java file, we cannot assess it
		return false, scanner_errors.GetInsufficientInformationError("cannot evaluate due to missing evidence/occurrences in BOM", javaSecurityPlugin.GetName(), "component", component.Name)
	}

	for _, occurrence := range *component.Evidence.Occurrences {
		if filepath.Ext(occurrence.Location) == ".java" {
			return true, nil
		}
	}

	slog.Warn("Current version of CICS does not take dynamic changes of java security properties (e.g. via System.setProperty) into account. Use with caution!")
	// TODO: Check if security property were changed dynamically via System.setProperty

	return false, nil
}

// Update a single component; returns nil if component is not allowed
func (javaSecurityPlugin *JavaSecurityPlugin) updateComponent(component cdx.Component) (updatedComponent *cdx.Component, additionalComponentsToDelete []cdx.BOMReference, err error) {

	ok, err := javaSecurityPlugin.isComponentAffectedByConfig(component)

	if !ok || go_errors.Is(err, scanner_errors.ErrInsufficientInformation) {
		return &component, []cdx.BOMReference{}, err
	}

	switch component.CryptoProperties.AssetType {
	case cdx.CryptoAssetTypeProtocol:
		return javaSecurityPlugin.security.updateProtocolComponent(component)
	default:
		return &component, []cdx.BOMReference{}, nil
	}
}
