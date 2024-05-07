package config

import (
	"bufio"
	"strings"
	cdx "github.com/CycloneDX/cyclonedx-go"
)

type Config interface {
	GetName() string
	IsComponentValid(cdx.Component) bool
}

type ConfigPlugin interface {
	IsConfigFile(path string) bool
	GetConfigFromFile(path string) Config
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