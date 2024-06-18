package javasecurity

import (
	go_errors "errors"
	"fmt"
	"ibm/container_cryptography_scanner/provider/filesystem"
	"ibm/container_cryptography_scanner/scanner/confidencelevel"
	scanner_errors "ibm/container_cryptography_scanner/scanner/errors"
	"log/slog"
	"path/filepath"

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
func (javaSecurityPlugin *JavaSecurityPlugin) UpdateComponents(components []cdx.Component) ([]cdx.Component, error) {
	javaSecurityPlugin.security.createCryptoComponentBOMRefMap(components)

	insufficientInformationErrors := []error{}
	var updatedComponents []cdx.Component

	for _, component := range components {
		if component.Type == cdx.ComponentTypeCryptographicAsset {
			if component.CryptoProperties != nil {

				componentWithDefaultConfidence := componentWithConfidence{
					Component:  &component,
					confidence: confidencelevel.New(),
				}

				updatedComponent, alsoAffected, err := javaSecurityPlugin.updateComponent(componentWithDefaultConfidence)

				if err != nil {
					if go_errors.Is(err, scanner_errors.ErrInsufficientInformation) {
						insufficientInformationErrors = append(insufficientInformationErrors, err)
					} else {
						return nil, fmt.Errorf("scanner java: error while updating component %v\n%w", component, err)
					}
				}

				prop := updatedComponent.confidence.GetProp()
				addPropertyOrCreateNew(updatedComponent.Component, prop)

				for ref, confidence := range alsoAffected {
					comp, ok := javaSecurityPlugin.security.bomRefMap[ref]
					if ok {
						affectedProp := confidence.GetProp()
						addPropertyOrCreateNew(comp, affectedProp)
					} else {
						slog.Warn("BOM-REF could not be resolved to component. Does the BOM File contain BOM-REFs that are not valid or cannot be resolved in the file itself?", "bom-ref", ref)
					}
				}

				updatedComponents = append(updatedComponents, *updatedComponent.Component)

			} else {
				slog.Info("Component is a crypto asset but has empty properties. Cannot evaluate that. Continuing.", "component", component.Name)
			}
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

	return updatedComponents, nil
}

// Assesses if the component is from a source affected by this type of config (e.g. a java file), requires "Evidence" and "Occurrences" to be present in the BOM
func (javaSecurityPlugin *JavaSecurityPlugin) isComponentAffectedByConfig(component componentWithConfidence) (bool, error) {
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
func (javaSecurityPlugin *JavaSecurityPlugin) updateComponent(component componentWithConfidence) (updatedComponent componentWithConfidence, additionalComponentsAffected affectedAlgorithmsWithConfidence, err error) { // TODO: additionalComponents..

	ok, err := javaSecurityPlugin.isComponentAffectedByConfig(component)

	if !ok || go_errors.Is(err, scanner_errors.ErrInsufficientInformation) {
		return component, affectedAlgorithmsWithConfidence{}, err
	}

	switch component.CryptoProperties.AssetType {
	case cdx.CryptoAssetTypeProtocol:
		return javaSecurityPlugin.security.updateProtocolComponent(component)
	default:
		return component, affectedAlgorithmsWithConfidence{}, nil
	}
}

func addPropertyOrCreateNew(comp *cdx.Component, prop cdx.Property) {
	if comp.Properties == nil {
		comp.Properties = new([]cdx.Property)
	}
	*comp.Properties = append(*comp.Properties, prop)
}
