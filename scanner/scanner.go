package scanner

import (
	"ibm/container_cryptography_scanner/scanner/config"
	openssl_conf "ibm/container_cryptography_scanner/scanner/openssl"
	"ibm/container_cryptography_scanner/scanner/javasecurity"
	"io/fs"
	"log"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func Check(e error) {
	if e != nil {
		panic(e)
	}
}

type scanner struct {
	configPlugins []config.ConfigPlugin
	configs       []config.Config
	directoryPath string
}

func (scanner *scanner) configWalkDirFunc(path string, d fs.DirEntry, err error) error {
	if !d.IsDir() {
		for _, plugin := range scanner.configPlugins {
			Check(err)
			if plugin.IsConfigFile(path) {
				config := plugin.GetConfigFromFile(path)
				scanner.configs = append(scanner.configs, config)
			}
		}
	}
	return err
}

func (scanner *scanner) findConfigFiles() {
	err := filepath.WalkDir(scanner.directoryPath, scanner.configWalkDirFunc)
	Check(err)
}

func mapToSlice(m map[cdx.Component]struct{}) []cdx.Component {
	keys := make([]cdx.Component, len(m))

	i := 0
	for k := range m {
		keys[i] = k
		i++
	}
	return keys
}

func (scanner *scanner) Scan(bom cdx.BOM) cdx.BOM {
	scanner.findConfigFiles()

	valid_components := make(map[cdx.Component]struct{}) // This seems odd but is the go-ish way of implementing sets (which valid_components is) since we often need to check whether the maps contains something (see https://stackoverflow.com/a/10486196)

	for _, config := range scanner.configs {
		for _, component := range *bom.Components {
			_, ok := valid_components[component]
			if !ok && 
			component.Type == cdx.ComponentTypeCryptographicAsset && 
			component.CryptoProperties != nil {
				if config.IsComponentValid(component) {
					valid_components[component] = struct{}{}
				} else {
					log.Default().Printf("The following component is not valid due to %v config:\n%+v", config.GetName(), component)
				}
			}
		}
	}

	*bom.Components = mapToSlice(valid_components)
	return bom
}

func NewScanner(directoryPath string) scanner {
	scanner := scanner{}
	scanner.configPlugins = []config.ConfigPlugin{
		&openssl_conf.OpenSSLPlugin{},
		&javasecurity.JavaSecurityPlugin{},
	}
	scanner.directoryPath = directoryPath

	return scanner
}
