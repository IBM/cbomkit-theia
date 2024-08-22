// Copyright 2024 IBM
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

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
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	v1 "github.com/google/go-containerregistry/pkg/v1"
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
func (JavaSecurityPlugin) GetName() string {
	return "java.security Plugin"
}

func (JavaSecurityPlugin) GetExplanation() string {
	return "Verify the executability of cryptographic assets from Java code\nAdds a confidence level (0-100) to the CBOM components to show how likely it is that this component is actually executable"
}

// Get the type of the plugin
func (JavaSecurityPlugin) GetType() plugins.PluginType {
	return plugins.PluginTypeVerify
}

// High-level function to update a list of components (e.g. remove components and add new ones) based on the underlying filesystem
func (javaSecurityPlugin *JavaSecurityPlugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	slog.Warn("Current version of CICS does not take dynamic changes of java security properties (e.g. via System.setProperty) into account. Use with caution!")

	if bom.Components == nil {
		return nil
	}

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
		return err
	}

	dockerConfig, ok := fs.GetConfig()
	var configuration *properties.Properties
	if ok && len(configurations) > 1 {
		configuration = javaSecurityPlugin.chooseMostLikelyConfiguration(configurations, dockerConfig)
	} else {
		configuration = chooseFirstConfiguration(configurations)
	}

	security, err := newJavaSecurity(configuration, fs)

	if err != nil {
		return err
	}

	insufficientInformationErrors := []error{}

	advancedCompSlice := advancedcomponentslice.FromComponentSlice(*bom.Components)

	for i, comp := range *bom.Components {
		if comp.Type == cdx.ComponentTypeCryptographicAsset {
			if comp.CryptoProperties != nil {
				err := security.updateComponent(i, advancedCompSlice)
				if err != nil {
					if go_errors.Is(err, scanner_errors.ErrInsufficientInformation) {
						insufficientInformationErrors = append(insufficientInformationErrors, err)
					} else {
						return fmt.Errorf("scanner java: error while updating component %v\n%w", advancedCompSlice.GetByIndex(i).Name, err)
					}
				}

				slog.Debug("Component has been analyzed and confidence has been set", "component", advancedCompSlice.GetByIndex(i).Name, "confidence", advancedCompSlice.GetByIndex(i).Confidence.GetValue())
			} else {
				slog.Debug("Component is a crypto asset but has empty properties. Cannot evaluate that. Continuing.", "component", advancedCompSlice.GetByIndex(i).Name)
			}
		}
	}

	joinedinsufficientInformationErrors := go_errors.Join(insufficientInformationErrors...)
	if joinedinsufficientInformationErrors != nil {
		slog.Warn("Run finished with insufficient information errors", "errors", go_errors.Join(insufficientInformationErrors...).Error())
	}

	*bom.Components = advancedCompSlice.GetComponentSlice()

	return nil
}

func chooseFirstConfiguration(configurations map[string]*properties.Properties) *properties.Properties {
	// Choose the first one
	for _, prop := range configurations {
		return prop
	}

	return nil
}

func (*JavaSecurityPlugin) chooseMostLikelyConfiguration(configurations map[string]*properties.Properties, dockerConfig v1.Config) (chosenProp *properties.Properties) {
	jdkPath, ok := getJDKPath(dockerConfig)
	if !ok {
		return chooseFirstConfiguration(configurations)
	}

	for path, conf := range configurations {
		if strings.HasPrefix(path, jdkPath) {
			return conf
		}
	}

	return chooseFirstConfiguration(configurations)
}

func getJDKPath(dockerConfig v1.Config) (value string, ok bool) {
	jdkPath, ok := getJDKPathFromEnvironmentVariables(dockerConfig.Env)
	if ok {
		return jdkPath, true
	}

	jdkPath, ok = getJDKPathFromRunCommand(dockerConfig)
	if ok {
		return jdkPath, true
	}

	return "", false
}

func getJDKPathFromEnvironmentVariables(envVariables []string) (value string, ok bool) {
	for _, env := range envVariables {
		keyAndValue := strings.Split(env, "=")
		key := keyAndValue[0]
		value := keyAndValue[1]

		switch key {
		case "JAVA_HOME", "JDK_HOME":
			return value, true
		case "JRE_HOME":
			return filepath.Dir(value), true
		default:
			continue
		}
	}

	return "", false
}

const LINE_SEPARATOR = "/"

func getJDKPathFromRunCommand(dockerConfig v1.Config) (value string, ok bool) {
	for _, s := range append(dockerConfig.Cmd, dockerConfig.Entrypoint...) {
		if strings.Contains(s, "java") {
			// Try to extract only the binary path
			fields := strings.Fields(s)
			if len(fields) > 0 {
				path := fields[0]
				pathList := strings.Split(path, LINE_SEPARATOR)
				for i, pathElement := range pathList {
					if strings.Contains(pathElement, "jdk") {
						return LINE_SEPARATOR + filepath.Join(pathList[:i+1]...), true
					}
				}
			}
		}
	}

	return "", false
}
