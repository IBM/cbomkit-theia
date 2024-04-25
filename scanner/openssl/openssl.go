package openssl

import (
	"bufio"
	"ibm/container_cryptography_scanner/scanner/config"
	"log"
	"os"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type OpenSSLPlugin struct {
}

func (openSSLPlugin OpenSSLPlugin) IsConfigFile(path string) bool {
	return true
}

func (openSSLPlugin OpenSSLPlugin) GetConfigFromFile(path string) config.Config {
	content, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return ParseOpensslConf(string(content))
}

type Section struct {
	sectionTitle string
	raw          map[string]string
	subSections  []Section
}

func (section Section) GetName() string {
	return "OpenSSL"
}

func (section Section) IsComponentValid(cdx.Component) bool {
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
		scanable := true
		for scanable {
			current_line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(current_line, "[") && strings.HasSuffix(current_line, "]") {
				extractedKey := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(current_line, "["), "]"))
				if extractedKey == sectionKey {
					break
				}
			}
			scanable = scanner.Scan()
		}

		if !scanable { // We did not find the sectionKey
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

func removeComments(input string) string {
	scanner := bufio.NewScanner(strings.NewReader(input))

	var result string

	for scanner.Scan() {
		currentLine := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(currentLine, "#") && currentLine != "" {
			result += currentLine + "\n"
		}
	}

	return result
}

func ParseOpensslConf(fileContent string) Section {
	fileContent = removeComments(fileContent)
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
