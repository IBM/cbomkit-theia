package javasecurity

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/magiconair/properties"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

/*
=======
General
=======
*/

// Checks single files while walking a file tree and parses a config if possible
func (javaSecurityPlugin *JavaSecurityPlugin) configWalkDirFunc(path string) (err error) {
	if javaSecurityPlugin.isConfigFile(path) {
		content, err := javaSecurityPlugin.filesystem.ReadFile(path)
		if err != nil {
			return err
		}
		config := properties.MustLoadString(string(content))
		javaSecurityPlugin.security = JavaSecurity{
			config,
			make(map[cdx.BOMReference]*cdx.Component),
			[]JavaSecurityAlgorithmRestriction{},
		}
	}

	return err
}

// Checks whether the current file at path is a java.security config file
func (javaSecurityPlugin *JavaSecurityPlugin) isConfigFile(path string) bool {
	// Check if this file is the java.security file and if that is the case extract the path of the active crypto.policy files
	// TODO: Make this smart so that it does not just take the first file that is a java.security file
	ext := filepath.Ext(path)
	return ext == ".security"
}

/*
=======
java.security related
=======
*/

// JavaSecurity represents the java.security file(s) found on the system
type JavaSecurity struct {
	*properties.Properties
	bomRefMap             map[cdx.BOMReference]*cdx.Component
	tlsDisablesAlgorithms []JavaSecurityAlgorithmRestriction
}

// TODO: Include Java JDK to make sure that it is even using the disabledAlgorithms Properties (most is only supported by OpenJDK)

// Creates a map from BOMReferences to Components to allow for fast reference
func (javaSecurity *JavaSecurity) createCryptoComponentBOMRefMap(components []cdx.Component) {
	javaSecurity.bomRefMap = make(map[cdx.BOMReference]*cdx.Component)
	for _, component := range components {
		if component.BOMRef != "" {
			javaSecurity.bomRefMap[cdx.BOMReference(component.BOMRef)] = &component
		}
	}
}

func removeFromSlice[T interface{}](slice []T, s int) []T {
	return append(slice[:s], slice[s+1:]...)
}

func (javaSecurity *JavaSecurity) getPropertyValues(key string) (values []string) {
	if javaSecurity.Properties == nil {
		return values
	}

	fullString, ok := javaSecurity.Get(key)
	if ok {
		values = strings.Split(fullString, ",")
		for i, value := range values {
			values[i] = strings.TrimSpace(value)
		}
	}
	toBeRemoved := []int{}
	for i, value := range values {
		if strings.HasPrefix(value, "include") {
			toBeRemoved = append(toBeRemoved, i)
			split := strings.Split(value, " ")
			if len(split) > 1 {
				values = append(values, javaSecurity.getPropertyValues(split[1])...)
			}
		}
	}
	for _, remove := range toBeRemoved {
		values = removeFromSlice(values, remove)
	}
	return values
}

// Parses the TLS Rules from the java.security file
func (javaSecurity *JavaSecurity) extractTLSRules() (err error) {
	algorithms := javaSecurity.getPropertyValues("jdk.tls.disabledAlgorithms")
	if len(algorithms) > 0 {
		for _, algorithm := range algorithms {
			keySize := 0
			keySizeOperator := keySizeOperatorNone
			name := algorithm

			// TODO: Include directives other than "keySize" (see java.security for reference)
			if strings.Contains(algorithm, "jdkCA") ||
				strings.Contains(algorithm, "denyAfter") ||
				strings.Contains(algorithm, "usage") {
				log.Default().Printf("Found constraint in java.security that is not supported: %v continuing", algorithm)
				continue
			}

			if strings.Contains(algorithm, "keySize") {
				split := strings.Split(algorithm, "keySize")
				if len(split) > 2 {
					return fmt.Errorf("scanner: sanity check failed, %v contains too many elements", split)
				}
				name = strings.TrimSpace(split[0])
				split[1] = strings.TrimSpace(split[1])
				keyRestrictions := strings.Split(split[1], " ")

				switch keyRestrictions[0] {
				case "<=":
					keySizeOperator = keySizeOperatorLowerEqual
				case "<":
					keySizeOperator = keySizeOperatorLower
				case "==":
					keySizeOperator = keySizeOperatorEqual
				case "!=":
					keySizeOperator = keySizeOperatorNotEqual
				case ">=":
					keySizeOperator = keySizeOperatorGreaterEqual
				case ">":
					keySizeOperator = keySizeOperatorGreater
				case "":
					keySizeOperator = keySizeOperatorNone
				default:
					return fmt.Errorf("scanner: could not parse the following keySizeOperator %v", keyRestrictions[0])
				}

				keySize, err = strconv.Atoi(keyRestrictions[1])
				if err != nil {
					return err
				}
			}

			javaSecurity.tlsDisablesAlgorithms = append(javaSecurity.tlsDisablesAlgorithms, JavaSecurityAlgorithmRestriction{
				name:            name,
				keySize:         keySize,
				keySizeOperator: keySizeOperator,
			})
		}
	}

	return nil
}

/*
=======
container image related
=======
*/

const SECURITY_CMD_ARGUMENT = "-Djava.security.properties="

// Checks the Dockerfile for potentially relevant information and adds it to the plugin

func (javaSecurityPlugin *JavaSecurityPlugin) checkDockerfile() error {
	path, ok := javaSecurityPlugin.filesystem.GetDockerfilePath()
	if !ok {
		return nil
	}
	reader, err := os.Open(path)
	if err != nil {
		return err
	}
	// We use the docker package to offload some work and do the validation there
	result, err := parser.Parse(reader)
	if err != nil {
		return err
	}
	result.PrintWarnings(os.Stderr)
	stages, _, err := instructions.Parse(result.AST)
	if err != nil {
		return err
	}
	// By now, the docker package should have validated the correctness of the file

	if len(stages) < 1 { // This Dockerfile is empty
		return err
	}

	return javaSecurityPlugin.checkForAdditionalSecurityFilesCMDParameter(stages)
}

func (javaSecurityPlugin *JavaSecurityPlugin) checkForAdditionalSecurityFilesCMDParameter(stages []instructions.Stage) (err error) {
	// We have to check if adding additional security files via CMD is even allowed via the java.security file (security.overridePropertiesFile property)

	if javaSecurityPlugin.security.Properties == nil { // We do not have a security file
		return nil
	}

	allowAdditionalFiles := javaSecurityPlugin.security.GetBool("security.overridePropertiesFile", true)
	if !allowAdditionalFiles {
		return nil
	}

	// Now, let's check for additional files added via CMD
	var value string
	var override bool
	var ok bool

	for _, command := range stages[0].Commands {
		switch v := command.(type) {
		case *instructions.EntrypointCommand: // TODO: Support for ENV Variables
			value, override, ok = getJavaFlagValue(v.ShellDependantCmdLine, SECURITY_CMD_ARGUMENT)
		case *instructions.CmdCommand:
			value, override, ok = getJavaFlagValue(v.ShellDependantCmdLine, SECURITY_CMD_ARGUMENT)
		}

		if ok {
			if override {
				javaSecurityPlugin.security = JavaSecurity{
					properties.NewProperties(), // We override the current loaded ini files with an empty object
					javaSecurityPlugin.security.bomRefMap,
					javaSecurityPlugin.security.tlsDisablesAlgorithms,
				}
			}

			content, err := javaSecurityPlugin.filesystem.ReadFile(value)
			if err != nil {
				return err
			}
			newProperties := properties.MustLoadString(string(content))
			javaSecurityPlugin.security.Merge(newProperties)
			return err
		}
	}

	return err
}

func getJavaFlagValue(command instructions.ShellDependantCmdLine, flag string) (value string, overwrite bool, ok bool) {
	for _, str := range command.CmdLine {
		split := strings.Split(str, flag)
		if len(split) == 2 {
			split = strings.Fields(split[1])
			value = split[0]
			if strings.HasPrefix(value, "=") { // The assignment is
				overwrite = true
				value = value[1:]
			}
			return value, overwrite, true
		}
	}
	return value, overwrite, false
}
