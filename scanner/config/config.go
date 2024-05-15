package config

import (
	"ibm/container_cryptography_scanner/provider/docker"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type ConfigPlugin interface {
	GetName() string
	ParseConfigsFromFilesystem(scannableImage docker.ScannableImage) error
	UpdateComponents(components []cdx.Component) (updatedComponents []cdx.Component, err error)
}
