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

package scanner

import (
	"fmt"
	"ibm/container-image-cryptography-scanner/provider/cyclonedx"
	"ibm/container-image-cryptography-scanner/provider/filesystem"
	plugin_package "ibm/container-image-cryptography-scanner/scanner/plugins"
	"ibm/container-image-cryptography-scanner/scanner/plugins/certificates"
	"ibm/container-image-cryptography-scanner/scanner/plugins/javasecurity"
	"ibm/container-image-cryptography-scanner/scanner/plugins/secrets"
	"log"
	"log/slog"
	"os"
	"slices"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"go.uber.org/dig"
)

type ScannerParameterStruct struct {
	dig.In

	Fs            filesystem.Filesystem
	Target        *os.File
	BomFilePath   string                  `name:"bomFilePath"`
	BomSchemaPath string                  `name:"bomSchemaPath"`
	Plugins       []plugin_package.Plugin `group:"plugins"`
}

func GetAllPluginConstructors() map[string]plugin_package.PluginConstructor {
	return map[string]plugin_package.PluginConstructor{
		"certificates": certificates.NewCertificatePlugin,
		"javasecurity": javasecurity.NewJavaSecurityPlugin,
		"secrets":      secrets.NewSecretsPlugin,
	}
}

// High-level function to do most heavy lifting for scanning a filesystem with a BOM. Output is written to target.
func CreateAndRunScan(params ScannerParameterStruct) error {
	var bom *cdx.BOM
	if params.BomFilePath != "" {
		var err error
		bom, err = cyclonedx.ParseBOM(params.BomFilePath, params.BomSchemaPath)
		if err != nil {
			return err
		}
	} else {
		bom = cdx.NewBOM()
		bom.Metadata = &cdx.Metadata{
			Timestamp: time.Now().Format(time.RFC3339),
		}
		bom.SerialNumber = "urn:uuid:" + uuid.New().String()
	}

	scanner := newScanner(params.Plugins)
	newBom, err := scanner.scan(*bom, params.Fs)
	if err != nil {
		return err
	}

	scanner.addMetadata(&newBom)

	log.Default().Println("FINISHED SCANNING")

	err = cyclonedx.WriteBOM(&newBom, params.Target)

	if err != nil {
		return err
	}

	return err
}

// scanner is used internally to represent a single scanner with several plugins (e.g. java.security plugin) scanning a single filesystem (e.g. a docker image layer)
type scanner struct {
	configPlugins []plugin_package.Plugin
}

// Scan a single BOM using all plugins
func (scanner *scanner) scan(bom cdx.BOM, fs filesystem.Filesystem) (cdx.BOM, error) {
	var err error
	if bom.Components == nil {
		slog.Info("bom does not have any components, this scan will only add components", "bom-serial-number", bom.SerialNumber)
		bom.Components = new([]cdx.Component)
	}

	// Sort the plugins based on the plugin type
	slices.SortFunc(scanner.configPlugins, func(a plugin_package.Plugin, b plugin_package.Plugin) int {
		return int(a.GetType()) - int(b.GetType())
	})

	for _, plugin := range scanner.configPlugins {
		slog.Info("Updating components", "plugin", plugin.GetName())
		err = plugin.UpdateBOM(fs, &bom)
		if err != nil {
			return bom, fmt.Errorf("scanner: plugin (%v) failed to updated components of bom; %w", plugin.GetName(), err)
		}
	}
	return bom, nil
}

// Create a new scanner object for the specific filesystem
func newScanner(plugins []plugin_package.Plugin) scanner {
	slog.Debug("Initializing a new scanner", "plugins", plugin_package.PluginSliceToString(plugins))
	return scanner{
		configPlugins: plugins,
	}
}

// Add Metadata to the BOM
func (scanner *scanner) addMetadata(bom *cdx.BOM) {
	if bom.Metadata == nil {
		bom.Metadata = new(cdx.Metadata)
	}
	if bom.Metadata.Tools == nil {
		bom.Metadata.Tools = new(cdx.ToolsChoice)
	}
	if bom.Metadata.Tools.Services == nil {
		services := make([]cdx.Service, 0, 1)
		bom.Metadata.Tools.Services = &services
	}

	pluginServices := make([]cdx.Service, len(scanner.configPlugins))
	for i, plugin := range scanner.configPlugins {
		pluginServices[i] = cdx.Service{
			Name: plugin.GetName(),
		}
	}

	*bom.Metadata.Tools.Services = append(*bom.Metadata.Tools.Services, cdx.Service{
		Provider: &cdx.OrganizationalEntity{
			Name: "IBM Research",
		},
		Name:     "Container Image Cryptography Scanner - CICS",
		Version:  "0.8",
		Services: &pluginServices,
	})
}
