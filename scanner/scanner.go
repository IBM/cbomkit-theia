package scanner

import (
	"fmt"
	"ibm/container_cryptography_scanner/provider/cyclonedx"
	"ibm/container_cryptography_scanner/provider/filesystem"
	"ibm/container_cryptography_scanner/scanner/config"
	"ibm/container_cryptography_scanner/scanner/plugins/javasecurity"
	"ibm/container_cryptography_scanner/scanner/plugins/files"
	"log"
	"log/slog"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// High-level function to do most heavy lifting for scanning a filesystem with a BOM. Output is written to target.
func CreateAndRunScan(fs filesystem.Filesystem, target *os.File, bomFilePath string, bomSchemaPath string) error {
	bom, err := cyclonedx.ParseBOM(bomFilePath, bomSchemaPath)

	if err != nil {
		return err
	}

	scanner := newScanner(fs)
	newBom, err := scanner.scan(*bom)
	if err != nil {
		return err
	}

	log.Default().Println("FINISHED SCANNING")

	err = cyclonedx.WriteBOM(&newBom, target)

	if err != nil {
		return err
	}

	return err
}

// scanner is used internally to represent a single scanner with several plugins (e.g. java.security plugin) scanning a single filesystem (e.g. a docker image layer)
type scanner struct {
	configPlugins []config.Plugin
	filesystem    filesystem.Filesystem
}

// Call all plugins for this scanner to find config files in the underlying filesystem
func (scanner *scanner) findConfigFiles() error {
	for _, plugin := range scanner.configPlugins {
		slog.Info("Finding config files", "plugin", plugin.GetName())
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
		err := fmt.Errorf("scanner: bom does not have any components")
		return cdx.BOM{}, err
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
func newScanner(filesystem filesystem.Filesystem) scanner {
	slog.Debug("Initializing a new scanner from filesystem", "filesystem", filesystem)
	scanner := scanner{}
	scanner.configPlugins = []config.Plugin{
		&javasecurity.JavaSecurityPlugin{},
		&files.FilePlugin{},
	}
	scanner.filesystem = filesystem

	return scanner
}
