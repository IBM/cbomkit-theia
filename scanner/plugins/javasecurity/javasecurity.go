package javasecurity

import (
	go_errors "errors"
	"fmt"
	"ibm/container-image-cryptography-scanner/provider/filesystem"
	advancedcomponentslice "ibm/container-image-cryptography-scanner/scanner/advanced-component-slice"
	scanner_errors "ibm/container-image-cryptography-scanner/scanner/errors"
	"ibm/container-image-cryptography-scanner/scanner/plugins"	
	"log/slog"
	"os"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/magiconair/properties"
)

// Represents the java security plugin in a specific scanning context
// Implements the config/ConfigPlugin interface
type JavaSecurityPlugin struct {}

// Get the name of the plugin for debugging purposes
func (javaSecurityPlugin *JavaSecurityPlugin) GetName() string {
	return "java.security Plugin"
}

// Get the type of the plugin
func (javaSecurityPlugin *JavaSecurityPlugin) GetType() plugins.PluginType {
	return plugins.PluginTypeVerify
}

// Parses all relevant information from the filesystem and creates underlying data structure for evaluation
func NewJavaSecurityPlugin() (plugins.Plugin, error) {
	return &JavaSecurityPlugin{}, nil
}

// High-level function to update a list of components (e.g. remove components and add new ones)
func (javaSecurityPlugin *JavaSecurityPlugin) UpdateComponents(fs filesystem.Filesystem, components []cdx.Component) ([]cdx.Component, error) {
	properties.ErrorHandler = func(err error) {
		slog.Error("Fatal error occurred during parsing of the java.security file", "err", err.Error())
		os.Exit(1)
	}

	configurations := make(map[string]*properties.Properties)

	err := fs.WalkDir(
		func(path string) (err error) {
			if javaSecurityPlugin.isConfigFile(path) {
				slog.Info("Adding java.security config file", "path", path)
				content, err := fs.ReadFile(path)
				if err != nil {
					return scanner_errors.GetParsingFailedAlthoughCheckedError(err, javaSecurityPlugin.GetName())
				}
				config, err := properties.LoadString(string(content))
				if err != nil {
					return scanner_errors.GetParsingFailedAlthoughCheckedError(err, javaSecurityPlugin.GetName())
				}

				configurations[path] = config
			}

			return err
		})

	if err != nil {
		return []cdx.Component{}, err
	}

	configuration := chooseMostLikelyConfiguration(configurations)

	security, err := newJavaSecurity(configuration, fs)

	insufficientInformationErrors := []error{}

	advancedCompSlice := advancedcomponentslice.FromComponentSlice(components)

	for i, comp := range components {
		if comp.Type == cdx.ComponentTypeCryptographicAsset {
			if comp.CryptoProperties != nil {
				err := security.updateComponent(i, advancedCompSlice)

				slog.Debug("Component has been analyzed and confidence has been set", "component", advancedCompSlice.GetByIndex(i).Name, "confidence", advancedCompSlice.GetByIndex(i).Confidence.GetValue())

				if err != nil {
					if go_errors.Is(err, scanner_errors.ErrInsufficientInformation) {
						insufficientInformationErrors = append(insufficientInformationErrors, err)
					} else {
						return nil, fmt.Errorf("scanner java: error while updating component %v\n%w", advancedCompSlice.GetByIndex(i).Name, err)
					}
				}
			} else {
				slog.Info("Component is a crypto asset but has empty properties. Cannot evaluate that. Continuing.", "component", advancedCompSlice.GetByIndex(i).Name)
			}
		}
	}

	joinedinsufficientInformationErrors := go_errors.Join(insufficientInformationErrors...)
	if joinedinsufficientInformationErrors != nil {
		slog.Warn("Run finished with insufficient information errors", "errors", go_errors.Join(insufficientInformationErrors...).Error())
	}

	return advancedCompSlice.GetComponentSlice(), nil
}

func chooseMostLikelyConfiguration(configurations map[string]*properties.Properties) *properties.Properties {
	// TODO: Do something useful here
	for _, prop := range configurations {
		return prop
	}
	return &properties.Properties{}
}

// Assesses if the component is from a source affected by this type of config (e.g. a java file), requires "Evidence" and "Occurrences" to be present in the BOM
func (javaSecurity *JavaSecurity) isComponentAffectedByConfig(component cdx.Component) (bool, error) {
	if component.Evidence == nil || component.Evidence.Occurrences == nil { // If there is no evidence telling us that whether this component comes from a java file, we cannot assess it
		return false, scanner_errors.GetInsufficientInformationError("cannot evaluate due to missing evidence/occurrences in BOM", "java.security Plugin", "component", component.Name)
	}

	for _, occurrence := range *component.Evidence.Occurrences {
		if filepath.Ext(occurrence.Location) == ".java" {
			return true, nil
		}
	}

	slog.Warn("Current version of CICS does not take dynamic changes of java security properties (e.g. via System.setProperty) into account. Use with caution!")
	return false, nil
}

// Update a single component; returns nil if component is not allowed
func (javaSecurity *JavaSecurity) updateComponent(index int, advancedcomponentslice *advancedcomponentslice.AdvancedComponentSlice) (err error) {

	ok, err := javaSecurity.isComponentAffectedByConfig(*advancedcomponentslice.GetByIndex(index).Component)

	if !ok || go_errors.Is(err, scanner_errors.ErrInsufficientInformation) {
		return err
	}

	switch advancedcomponentslice.GetByIndex(index).CryptoProperties.AssetType {
	case cdx.CryptoAssetTypeProtocol:
		return javaSecurity.updateProtocolComponent(index, advancedcomponentslice)
	default:
		return nil
	}
}
