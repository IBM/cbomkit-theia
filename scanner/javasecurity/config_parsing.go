package javasecurity

import (
	"fmt"
	"log"
	"path/filepath"
	"strconv"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/magiconair/properties"

	cdx "github.com/CycloneDX/cyclonedx-go"
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

// Checks the Docker Config for potentially relevant information and adds it to the plugin

func (javaSecurityPlugin *JavaSecurityPlugin) checkConfig() error {
	config, ok := javaSecurityPlugin.filesystem.GetConfig()
	if !ok {
		return nil
	}

	return javaSecurityPlugin.checkForAdditionalSecurityFilesCMDParameter(config)
}

func (javaSecurityPlugin *JavaSecurityPlugin) checkForAdditionalSecurityFilesCMDParameter(config v1.Config) (err error) {
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

	for _, command := range append(config.Cmd, config.Entrypoint...) {
		// TODO: Support for ENV Variables
		value, override, ok = getJavaFlagValue(command, SECURITY_CMD_ARGUMENT)

		if ok {
			if override {
				javaSecurityPlugin.security = JavaSecurity{
					properties.NewProperties(), // We override the current loaded property file with an empty object
					javaSecurityPlugin.security.bomRefMap,
					javaSecurityPlugin.security.tlsDisablesAlgorithms,
				}
			}

			content, err := javaSecurityPlugin.filesystem.ReadFile(value)
			if err != nil {
				if strings.Contains(err.Error(), "could not find file path in Tree") {
					log.Default().Printf("Failed to read file (%v) specific via a command in the image configuration. The image or image config is probably malformed. Continuing without adding it.", value)
					return nil
				} else {
					return err
				}
			}
			newProperties := properties.MustLoadString(string(content))
			javaSecurityPlugin.security.Merge(newProperties)
			return err
		}
	}

	return err
}

func getJavaFlagValue(command string, flag string) (value string, overwrite bool, ok bool) {
	split := strings.Split(command, flag)
	if len(split) == 2 {
		split = strings.Fields(split[1])
		value = split[0]
		if strings.HasPrefix(value, "=") {
			overwrite = true
			value = value[1:]
		}
		return value, overwrite, true
	}
	return value, overwrite, false
}
