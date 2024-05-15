package config

import (
	"bufio"
	"strings"
	"ibm/container_cryptography_scanner/provider/docker"
	cdx "github.com/CycloneDX/cyclonedx-go"
)

type ConfigPlugin interface {
	GetName() string
	ParseConfigsFromFilesystem(scannableImage docker.ScannableImage) error
	UpdateComponents(components []cdx.Component) (updatedComponents []cdx.Component, err error)
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