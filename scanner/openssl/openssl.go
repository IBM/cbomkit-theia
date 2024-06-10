package openssl

import (
	"bufio"
	"ibm/container_cryptography_scanner/provider/filesystem"
	go_errors "errors"
	scanner_errors "ibm/container_cryptography_scanner/scanner/errors"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/ini.v1"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type OpenSSLPlugin struct {
	configs    []*ini.File
	filesystem filesystem.Filesystem
}

func (openSSLPlugin *OpenSSLPlugin) GetName() string {
	return "OpenSSLConfig"
}

func (openSSLPlugin *OpenSSLPlugin) ParseConfigsFromFilesystem(filesystem filesystem.Filesystem) error {
	openSSLPlugin.filesystem = filesystem
	return filesystem.WalkDir(openSSLPlugin.configWalkDirFunc)
}

// TODO: Implement
func (openSSLPlugin *OpenSSLPlugin) UpdateComponents(components []cdx.Component) (updatedComponents []cdx.Component, err error) {
	return components, nil
}

// Internal

func (openSSLPlugin *OpenSSLPlugin) isConfigFile(path string) bool { // TODO: Make it more advanced
	ext := filepath.Ext(path)
	return ext == ".cnf" || ext == ".conf"
}

func (openSSLPlugin *OpenSSLPlugin) configWalkDirFunc(path string) (err error) {
	if openSSLPlugin.isConfigFile(path) {
		configBytes, err1 := openSSLPlugin.parseOpenSSLConfigFile(path)
		config, err2 := ini.Load(configBytes)
		if err := go_errors.Join(err1, err2); err != nil {
			return scanner_errors.GetParsingFailedAlthoughCheckedError(err, openSSLPlugin.GetName())
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
	case cdx.CryptoAssetTypeAlgorithm:
	case cdx.CryptoAssetTypeProtocol:
	case cdx.CryptoAssetTypeRelatedCryptoMaterial:
	case cdx.CryptoAssetTypeCertificate:
	default:
		return true
	}

	return true
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

	out, err = openSSLPlugin.filesystem.ReadFile(path)
	if err != nil {
		return []byte{}, err
	}

	out = beautifyConfig(out)

	return out, err
}
