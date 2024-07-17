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

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/magiconair/properties"
)

// Represents the java security plugin in a specific scanning context
// Implements the config/ConfigPlugin interface
type JavaSecurityPlugin struct{}

// Creates underlying data structure for evaluation
func NewJavaSecurityPlugin() (plugins.Plugin, error) {
	return &JavaSecurityPlugin{}, nil
}

// Get the name of the plugin for debugging purposes
func (javaSecurityPlugin *JavaSecurityPlugin) GetName() string {
	return "java.security Plugin"
}

// Get the type of the plugin
func (javaSecurityPlugin *JavaSecurityPlugin) GetType() plugins.PluginType {
	return plugins.PluginTypeVerify
}

// High-level function to update a list of components (e.g. remove components and add new ones) based on the underlying filesystem
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

	configuration := javaSecurityPlugin.chooseMostLikelyConfiguration(configurations)

	security, err := newJavaSecurity(configuration, fs)

	if err != nil {
		return []cdx.Component{}, err
	}

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

func (*JavaSecurityPlugin) chooseMostLikelyConfiguration(configurations map[string]*properties.Properties) *properties.Properties {
	// TODO: Do something useful here
	for _, prop := range configurations {
		return prop
	}
	return &properties.Properties{}
}
