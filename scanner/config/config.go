package config

import (
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
