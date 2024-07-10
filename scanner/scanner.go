package scanner

import (
	"fmt"
	"ibm/container-image-cryptography-scanner/provider/cyclonedx"
	"ibm/container-image-cryptography-scanner/provider/filesystem"
	"ibm/container-image-cryptography-scanner/scanner/plugins"
	"ibm/container-image-cryptography-scanner/scanner/plugins/certificates"
	"ibm/container-image-cryptography-scanner/scanner/plugins/javasecurity"
	"log"
	"log/slog"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"go.uber.org/dig"
)

type ScannerParameterStruct struct {
	dig.In

	Fs            filesystem.Filesystem
	Target        *os.File
	BomFilePath   string `name:"bomFilePath"`
	BomSchemaPath string `name:"bomSchemaPath"`
	Plugins       []plugins.Plugin
}

func GetAllPlugins() []plugins.Plugin {
	return []plugins.Plugin{
		&javasecurity.JavaSecurityPlugin{},
		&certificates.CertificatesPlugin{},
	}
}

// High-level function to do most heavy lifting for scanning a filesystem with a BOM. Output is written to target.
func CreateAndRunScan(params ScannerParameterStruct) error {
	bom, err := cyclonedx.ParseBOM(params.BomFilePath, params.BomSchemaPath)

	if err != nil {
		return err
	}

	scanner := newScanner(params.Fs, params.Plugins)
	newBom, err := scanner.scan(*bom)
	if err != nil {
		return err
	}

	log.Default().Println("FINISHED SCANNING")

	err = cyclonedx.WriteBOM(&newBom, params.Target)

	if err != nil {
		return err
	}

	return err
}

// scanner is used internally to represent a single scanner with several plugins (e.g. java.security plugin) scanning a single filesystem (e.g. a docker image layer)
type scanner struct {
	configPlugins []plugins.Plugin
	filesystem    filesystem.Filesystem
}

// Call all plugins for this scanner to find config files in the underlying filesystem
func (scanner *scanner) findConfigFiles() error {
	for _, plugin := range scanner.configPlugins {
		slog.Info("Finding relevant files", "plugin", plugin.GetName())
		err := plugin.ParseRelevantFilesFromFilesystem(scanner.filesystem)
		if err != nil {
			return err
		}
	}
	return nil
}

// Scan a single BOM using all plugins
func (scanner *scanner) scan(bom cdx.BOM) (cdx.BOM, error) {
	err := scanner.findConfigFiles()
	if err != nil {
		return cdx.BOM{}, err
	}

	if bom.Components == nil {
		slog.Info("bom does not have any components, this scan will only add components", "bom-serial-number", bom.SerialNumber)
		bom.Components = new([]cdx.Component)
	}

	for _, plugin := range scanner.configPlugins {
		slog.Info("Updating components", "plugin", plugin.GetName())
		*bom.Components, err = plugin.UpdateComponents(*bom.Components)
		if err != nil {
			return bom, fmt.Errorf("scanner: plugin (%v) failed to updated components of bom; %w", plugin.GetName(), err)
		}
	}
	return bom, nil
}

// Create a new scanner object for the specific filesystem
func newScanner(filesystem filesystem.Filesystem, plugins []plugins.Plugin) scanner {
	slog.Debug("Initializing a new scanner from filesystem", "filesystem", filesystem.GetIdentifier())
	scanner := scanner{}
	scanner.configPlugins = plugins
	scanner.filesystem = filesystem

	return scanner
}
