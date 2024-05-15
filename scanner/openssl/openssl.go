package openssl

import (
	"bufio"
	"ibm/container_cryptography_scanner/provider/docker"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/ini.v1"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type OpenSSLPlugin struct {
	configs        []*ini.File
	scannableImage docker.ScannableImage
}

func (openSSLPlugin *OpenSSLPlugin) GetName() string {
	return "OpenSSLConfig"
}

func (openSSLPlugin *OpenSSLPlugin) ParseConfigsFromFilesystem(scannableImage docker.ScannableImage) error {
	openSSLPlugin.scannableImage = scannableImage
	return filepath.WalkDir(scannableImage.Filesystem.Path, openSSLPlugin.configWalkDirFunc)
}

func (openSSLPlugin *OpenSSLPlugin) UpdateComponents(components []cdx.Component) (updatedComponents []cdx.Component, err error) { // Return
	return nil, nil
}

// Internal

func (openSSLPlugin *OpenSSLPlugin) isConfigFile(path string) bool { // TODO: Make it more advanced
	ext := filepath.Ext(path)
	return ext == ".cnf" || ext == ".conf"
}

func (openSSLPlugin *OpenSSLPlugin) configWalkDirFunc(path string, d fs.DirEntry, err error) error {
	if !d.IsDir() && openSSLPlugin.isConfigFile(path) {
		configBytes, err := openSSLPlugin.parseOpenSSLConfigFile(path)
		config, err := ini.Load(configBytes)
		if err != nil {
			return err
		}
		openSSLPlugin.configs = append(openSSLPlugin.configs, config)
	}
	return err
}

func (openSSLPlugin *OpenSSLPlugin) isComponentValid(component cdx.Component) bool {
	// First we need to assess if the component is even from a source affected by this type of config (e.g. a python file for example)

	if component.Evidence.Occurrences == nil { // If there is no evidence telling us that whether this component comes from a python file, we cannot assess it
		return true
	}

	occurrences := *component.Evidence.Occurrences

	var isComponentFromRelevantFile bool
	for _, occurrence := range occurrences {
		if filepath.Ext(occurrence.Location) == ".py" { // TODO: Maybe expand this for more files that follow OpenSSL config
			isComponentFromRelevantFile = true
			break
		}
	}

	if !isComponentFromRelevantFile {
		return true
	}

	// Now, we assess the assetType and move to further analysis
	switch component.CryptoProperties.AssetType {
	case cdx.AssetTypeAlgorithm:
		log.Default().Printf("Detected %v", component.CryptoProperties.AssetType)
	case cdx.AssetTypeProtocol:
		log.Default().Printf("Detected %v", component.CryptoProperties.AssetType)
	case cdx.AssetTypeRelatedCryptoMaterial:
		log.Default().Printf("Detected %v", component.CryptoProperties.AssetType)
	case cdx.AssetTypeCertificate:
		log.Default().Printf("Detected %v", component.CryptoProperties.AssetType)
	default:
		return true
	}

	return true
}

func trimAll(input []string) []string {
	for i, item := range input {
		input[i] = strings.TrimSpace(item)
	}
	return input
}

func replaceAtIndex(s []byte, toBeInserted []byte, start int, end int) []byte {
	s = append(s[:start], s[end:]...)
	s = slices.Insert(s, start, toBeInserted...)

	return s
}

func beautifyConfig(config []byte) []byte {
	scanner := bufio.NewScanner(strings.NewReader(string(config)))
	index := 0

	for scanner.Scan() {
		current_line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(current_line, "[") && strings.HasSuffix(current_line, "]") {
			notTrimmed := strings.TrimSuffix(strings.TrimPrefix(current_line, "["), "]")
			trimmed := strings.TrimSpace(notTrimmed)

			if trimmed != notTrimmed {
				config = replaceAtIndex(config, []byte("["+trimmed+"]"), index, index+len(scanner.Text()))
				index += (2 + len(trimmed)) - len(scanner.Text())
			}

		}
		index += len(scanner.Text()) + 1
	}

	return config

	/*
		TODO: Add support for variables (e.g. $var)
		TODO: Add support for pragma etc.
	*/
}

func (openSSLPlugin *OpenSSLPlugin) parseOpenSSLConfigFile(path string) (out []byte, err error) {

	out, err = os.ReadFile(path)

	out = beautifyConfig(out)

	return out, err
}
