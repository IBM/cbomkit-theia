package javasecurity

import (
	"bufio"
	"ibm/container_cryptography_scanner/provider/docker"
	"ibm/container_cryptography_scanner/scanner/config"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

const POLICY_CMD_ARGUMENT = "-Djava.security.policy="

type JavaSecurityPlugin struct {
	relevantPolicyDirs                   map[string]struct{} // Weird go-ish way of doing sets
	ignoreEverythingButCMDArgumentPolicy bool
	policies                             []Policy
	security                             map[string]string
	scannableImage                       docker.ScannableImage
}

func (javaSecurityPlugin *JavaSecurityPlugin) GetName() string {
	return "JavaSecurity Policy File"
}

func (javaSecurityPlugin *JavaSecurityPlugin) ParseConfigsFromFilesystem(scannableImage docker.ScannableImage) error {
	javaSecurityPlugin.scannableImage = scannableImage

	err := filepath.WalkDir(scannableImage.Filesystem.Path, javaSecurityPlugin.configWalkDirFunc)

	javaSecurityPlugin.checkDockerfile()

	return err
}

func (javaSecurityPlugin *JavaSecurityPlugin) UpdateComponents(components *[]cdx.Component) error {
	return nil
}

// Internal

func (javaSecurityPlugin *JavaSecurityPlugin) addToPolicyDirs(value string) (err error) {
	if javaSecurityPlugin.relevantPolicyDirs == nil {
		javaSecurityPlugin.relevantPolicyDirs = make(map[string]struct{})
	}
	if !javaSecurityPlugin.ignoreEverythingButCMDArgumentPolicy {
		javaSecurityPlugin.relevantPolicyDirs[value] = struct{}{}
	}
	return err
}

func (javaSecurityPlugin *JavaSecurityPlugin) getJavaPolicyFlagValue(command instructions.ShellDependantCmdLine) (ok bool) {
	for _, str := range command.CmdLine {
		index := strings.Index(str, POLICY_CMD_ARGUMENT)
		if index != -1 {
			ok = true
			firstPartCutOff := str[index+len(POLICY_CMD_ARGUMENT):]
			index = strings.Index(firstPartCutOff, " ") // TODO: Make this more secure
			value := firstPartCutOff[:index]
			if strings.HasPrefix(value, "=") { // The assignment is
				javaSecurityPlugin.ignoreEverythingButCMDArgumentPolicy = true
				value = value[1:]
				javaSecurityPlugin.relevantPolicyDirs = map[string]struct{}{ // Delete everything but that one entry
					value: {},
				}
				return ok
			}
			javaSecurityPlugin.addToPolicyDirs(value)
		}
	}
	return ok
}

func (javaSecurityPlugin *JavaSecurityPlugin) checkDockerfile() {
	reader, err := os.Open(javaSecurityPlugin.scannableImage.DockerfilePath)
	if err != nil {
		panic(err)
	}
	// We use the docker package to offload some work and do the validation there
	result, err := parser.Parse(reader)
	if err != nil {
		panic(err)
	}
	result.PrintWarnings(os.Stderr)
	stages, _, err := instructions.Parse(result.AST)
	if err != nil {
		panic(err)
	}
	log.Default().Print(stages)
	// By now, the docker package should have validated the correctness of the file

	if len(stages) < 1 { // This Dockerfile is empty
		return
	}

	for _, command := range stages[0].Commands {
		switch v := command.(type) {
		case *instructions.EntrypointCommand: // TODO: Support for ENV Variables
			javaSecurityPlugin.getJavaPolicyFlagValue(v.ShellDependantCmdLine)
		case *instructions.CmdCommand:
			javaSecurityPlugin.getJavaPolicyFlagValue(v.ShellDependantCmdLine)
		}
	}

}

func (javaSecurityPlugin *JavaSecurityPlugin) isConfigFile(path string) bool {
	// Check if this file is the java.security file and if that is the case extract the path of the active crypto.policy files
	ext := filepath.Ext(path)
	return ext == ".policy"
}

func (javaSecurityPlugin *JavaSecurityPlugin) configWalkDirFunc(path string, d fs.DirEntry, err error) error {
	if d.IsDir() {
		return nil
	}

	if javaSecurityPlugin.isConfigFile(path) {
		content, err := os.ReadFile(path)
		if err != nil {
			panic(err)
		}
		javaSecurityPlugin.policies = append(javaSecurityPlugin.policies, parseJavaPolicyFile(string(content)))
	}

	// Check for java.security file
	ext := filepath.Ext(path)
	if ext == ".security" {
		javaSecurityPlugin.parseJavaSecurityFile(path)
		value, ok := javaSecurityPlugin.security["crypto.policy"]
		if ok {
			javaSecurityPlugin.addToPolicyDirs(value)
		}
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
	var parameters []string

	if len(splitLine) >= 3 {
		parameters = strings.Split(splitLine[2], ",")
	}

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

func (javaSecurityPlugin *JavaSecurityPlugin) parseJavaSecurityFile(path string) {
	javaSecurityPlugin.security = make(map[string]string)
	pathFile, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	scanner := bufio.NewScanner(pathFile)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "//") {
			continue
		}
		text := strings.TrimSpace(scanner.Text())
		splittedLine := strings.Split(text, "=")

		// If this is true, this entry is weird and should be investigated
		if len(splittedLine) != 2 || splittedLine[1] == "" {
			log.Default().Printf("Cannot deal with the following entry: %+v \nContinuing...", splittedLine)
			javaSecurityPlugin.security[splittedLine[0]] = ""
			continue
		}

		value := splittedLine[1]
		for strings.HasSuffix(strings.TrimSpace(scanner.Text()), "\\") { // TODO: This is broken
			value = strings.TrimSuffix(value, "\\")
			scanner.Scan()
			var sb strings.Builder
			sb.WriteString(value)
			sb.WriteString(scanner.Text())
			value = sb.String()
		}
		javaSecurityPlugin.security[splittedLine[0]] = value
	}
}
