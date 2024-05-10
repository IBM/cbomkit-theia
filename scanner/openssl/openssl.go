package openssl

import (
	"bufio"
	"ibm/container_cryptography_scanner/scanner/config"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type OpenSSLPlugin struct {
	sections []Section
}

func (openSSLPlugin *OpenSSLPlugin) GetName() string {
	return "OpenSSLConfig"
}

func (openSSLPlugin *OpenSSLPlugin) ParseConfigsFromFilesystem(path string) error {
	return filepath.WalkDir(path, openSSLPlugin.configWalkDirFunc)
}

func (openSSLPlugin *OpenSSLPlugin) UpdateComponents(components *[]cdx.Component) error { // Return
	// (*components)[0] = cdx.Component{}
	return nil
}

// Internal

func (openSSLPlugin *OpenSSLPlugin) isConfigFile(path string) bool { // TODO: Make it more advanced
	ext := filepath.Ext(path)
	return ext == ".cnf" || ext == ".conf"
}

func (openSSLPlugin *OpenSSLPlugin) configWalkDirFunc(path string, d fs.DirEntry, err error) error {
	if !d.IsDir() && openSSLPlugin.isConfigFile(path) {
		content, err := os.ReadFile(path)
		if err != nil {
			panic(err)
		}
		openSSLPlugin.sections = append(openSSLPlugin.sections, parseOpensslConf(string(content)))
	}
	return err
}

type Section struct {
	sectionTitle string
	raw          map[string]string
	subSections  []Section
}

func (section Section) isComponentValid(component cdx.Component) bool {
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

func toMap(input string) map[string]string {
	scanner := bufio.NewScanner(strings.NewReader(input))

	res := make(map[string]string)

	for scanner.Scan() {
		current_line := strings.Split(scanner.Text(), "=")
		current_line = trimAll(current_line)
		if len(current_line) == 2 {
			res[current_line[0]] = current_line[1]
		}
	}

	return res
}

func getSection(searchable string, sectionKey string) (Section, bool) {
	scanner := bufio.NewScanner(strings.NewReader(searchable))

	if sectionKey != "" {
		scannable := true
		for scannable {
			current_line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(current_line, "[") && strings.HasSuffix(current_line, "]") {
				extractedKey := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(current_line, "["), "]"))
				if extractedKey == sectionKey {
					break
				}
			}
			scannable = scanner.Scan()
		}

		if !scannable { // We did not find the sectionKey
			return Section{}, false
		}
	}

	/*
		TODO: Add support for variables (e.g. $var)
	*/

	var result string
	for scanner.Scan() {
		current_line := scanner.Text()
		if strings.HasPrefix(current_line, "[") {
			break
		} else if !strings.HasPrefix(current_line, "#") && current_line != "" {
			result += scanner.Text()
			result += "\n"
		} else if strings.HasPrefix(current_line, ".include") || strings.HasPrefix(current_line, ".pragma") { // TODO: Implement inclusion of other config files
			log.Default().Println("\".include\" or \".pragma\" is currently not supported! Continuing...")
		}
	}

	section := Section{
		sectionTitle: sectionKey,
		raw:          toMap(result),
	}

	for _, value := range section.raw {
		subsection, ok := getSection(searchable, value)
		if ok {
			section.subSections = append(section.subSections, subsection)
		}
	}

	return section, true
}

func parseOpensslConf(fileContent string) Section {
	fileContent = config.RemoveComments(fileContent, "#")
	opensslConf, ok := getSection(fileContent, "")

	if !ok {
		log.Fatal("The OpenSSL Config is malformed. Exiting.")
	}

	/*
		targets := []string{
			"providers",
			"alg_section",
			"ssl_conf",
			"engines",
			"random",
		}

		for _, target := range targets {
			targetSectionKey, ok := opensslConfSection.raw[target]
			if ok {
				opensslConf[target] = getSection(fileContent, targetSectionKey)
				log.Default().Printf("Adding Target Section %v -> %v", target, opensslConf[target])
			}
		}  */

	log.Default().Printf("Parsed OpenSSL Config:\n%+v", opensslConf)

	return opensslConf
}
