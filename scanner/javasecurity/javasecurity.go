package javasecurity

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

type JavaSecurityPlugin struct {
	policyDirName string
	policies      []Policy
}

func (javaSecurityPlugin *JavaSecurityPlugin) GetName() string {
	return "JavaSecurity Policy File"
}

func (javaSecurityPlugin *JavaSecurityPlugin) ParseConfigsFromFilesystem(path string) error {
	return filepath.WalkDir(path, javaSecurityPlugin.configWalkDirFunc)
}

func (javaSecurityPlugin *JavaSecurityPlugin) UpdateComponents(components *[]cdx.Component) error {
	return nil
}

// Internal

func (javaSecurityPlugin *JavaSecurityPlugin) isConfigFile(path string) bool {
	// Check if this file is the java.security file and if that is the case extract the path of the active crypto.policy files
	ext := filepath.Ext(path)
	switch ext {
	case ".security":
		javaSecurityPlugin.policyDirName = getValueFromKey("crypto.policy", path)
		return false // We do not need any more information from this file TODO: Maybe expand this for TLS and so on to also include java.security file
	case ".policy":
		return true
	default:
		return false
	}
}

func (javaSecurityPlugin *JavaSecurityPlugin) configWalkDirFunc(path string, d fs.DirEntry, err error) error {
	if !d.IsDir() && javaSecurityPlugin.isConfigFile(path) {
		content, err := os.ReadFile(path)
		if err != nil {
			panic(err)
		}
		javaSecurityPlugin.policies = append(javaSecurityPlugin.policies, parseJavaPolicyFile(string(content)))
	}
	return err
}

type Policy struct {
	permissions []Permission
}

type Permission struct {
	raw                 string
	permissionClassName string
	parameters          []string
}

func parseJavaPolicyFile(fileContent string) Policy {
	fileContent = config.RemoveComments(fileContent, "//")
	_, fileContent, found := strings.Cut(fileContent, "{")
	if !found {
		log.Fatal("Did not find { in the policy file! Exiting...")
	}
	fileContent, _, found = strings.Cut(fileContent, "}") // Get only the part in the "grant {}" object
	if !found {
		log.Fatal("Did not find } in the policy file! Exiting...")
	}

	scanner := bufio.NewScanner(strings.NewReader(fileContent))
	scanner.Split(semicolonSplit)
	var policy Policy

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			policy.permissions = append(policy.permissions, getPermissionFromString(scanner.Text()))
		}
	}

	log.Default().Printf("Parsed Java Policy Config:\n%+v", policy)

	return policy
}

func semicolonSplit(data []byte, atEOF bool) (advance int, token []byte, err error) {

	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	if i := strings.Index(string(data), ";"); i >= 0 { // TODO: This could be problematic when ; is used in strings
		return i + 1, data[0:i], nil
	}

	if atEOF {
		return len(data), data, nil
	}

	return
}

func getPermissionFromString(line string) Permission {
	line = strings.TrimSpace(line)
	splitLine := strings.SplitAfterN(line, " ", 3)
	parameters := strings.Split(splitLine[2], ",")

	for i, parameter := range parameters {
		parameter = strings.TrimSpace(parameter)
		parameters[i] = strings.Trim(parameter, "\"")
	}

	return Permission{
		raw:                 line,
		permissionClassName: strings.TrimSpace(splitLine[1]),
		parameters:          parameters,
	}
}

func getValueFromKey(key string, path string) (value string) {
	pathFile, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	scanner := bufio.NewScanner(pathFile)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(text, key) {
			splittedLine := strings.Split(text, "=")

			// If this is true, this entry is weird and should be investigated
			if len(splittedLine) != 2 || splittedLine[1] == "" {
				log.Default().Printf("Cannot deal with the following entry: %+v \nContinuing...", splittedLine)
				break
			}

			value = splittedLine[1]
			for strings.HasSuffix(strings.TrimSpace(scanner.Text()), "\\") {
				value = strings.TrimSuffix(value, "\\")
				scanner.Scan()
				var sb strings.Builder
				sb.WriteString(value)
				sb.WriteString(scanner.Text())
				value = sb.String()
			}
			break
		}
	}
	return
}
