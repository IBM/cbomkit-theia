package config

import (
	"bufio"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type ConfigPlugin interface {
	GetName() string
	ParseConfigsFromFilesystem(path string) error
	UpdateComponents(components *[]cdx.Component) error
}

func RemoveComments(input string, commentPrefix string) string {
	scanner := bufio.NewScanner(strings.NewReader(input))

	var result string

	for scanner.Scan() {
		currentLine := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(currentLine, commentPrefix) && currentLine != "" {
			result += currentLine + "\n"
		}
	}

	return result
}

/*
func ValidateComponents(component cdx.Component) cdx.BOM {
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
} */
