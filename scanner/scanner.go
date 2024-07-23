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
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"go.uber.org/dig"
)

type ScannerParameterStruct struct {
	dig.In

	Fs            filesystem.Filesystem
	Target        *os.File
	BomFilePath   string           `name:"bomFilePath"`
	BomSchemaPath string           `name:"bomSchemaPath"`
	Plugins       []plugins.Plugin `group:"plugins"`
}

func GetAllPluginConstructors() map[string]plugins.PluginConstructor {
	return map[string]plugins.PluginConstructor{
		"certificates": certificates.NewCertificatePlugin,
		"javasecurity": javasecurity.NewJavaSecurityPlugin,
	}
}

// High-level function to do most heavy lifting for scanning a filesystem with a BOM. Output is written to target.
func CreateAndRunScan(params ScannerParameterStruct) error {
	bom, err := cyclonedx.ParseBOM(params.BomFilePath, params.BomSchemaPath)

	if err != nil {
		return err
	}

	scanner := newScanner(params.Plugins)
	newBom, err := scanner.scan(*bom, params.Fs)
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
}

// Scan a single BOM using all plugins
func (scanner *scanner) scan(bom cdx.BOM, fs filesystem.Filesystem) (cdx.BOM, error) {
	var err error
	if bom.Components == nil {
		slog.Info("bom does not have any components, this scan will only add components", "bom-serial-number", bom.SerialNumber)
		bom.Components = new([]cdx.Component)
	}

	// Sort the plugins based on the plugin type
	slices.SortFunc(scanner.configPlugins, func(a plugins.Plugin, b plugins.Plugin) int {
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
func newScanner(plugins []plugins.Plugin) scanner {
	slog.Debug("Initializing a new scanner", "plugins", plugins)
	return scanner{
		configPlugins: plugins,
	}
}
