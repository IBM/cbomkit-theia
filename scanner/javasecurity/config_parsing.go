package javasecurity

import (
	go_errors "errors"
	"fmt"
	"ibm/container_cryptography_scanner/provider/cyclonedx"
	scanner_errors "ibm/container_cryptography_scanner/scanner/errors"
	"log/slog"
	"os"
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
		slog.Info("Adding java.security config file", "path", path)
		content, err := javaSecurityPlugin.filesystem.ReadFile(path)
		if err != nil {
			return scanner_errors.GetParsingFailedAlthoughCheckedError(err, javaSecurityPlugin.GetName())
		}
		config := properties.MustLoadString(string(content)) // Sadly this function simply panics in case of any parsing errors. So no retry :sob:
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
	dir, _ := filepath.Split(path)
	dir = filepath.Clean(dir)

	// Check correct directory
	if !(strings.HasSuffix(dir, filepath.Join("jre", "lib", "security")) ||
		strings.HasSuffix(dir, filepath.Join("conf", "security"))) {
		return false
	}

	// Check file extension
	ext := filepath.Ext(path)
	if ext != ".security" {
		return false
	}

	// If all checks passed, return true
	return true
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
	slog.Debug("Creating new reference map to translate BOMReferences to components")
	javaSecurity.bomRefMap = make(map[cdx.BOMReference]*cdx.Component)
	for _, component := range components {
		if component.BOMRef != "" {
			javaSecurity.bomRefMap[cdx.BOMReference(component.BOMRef)] = &component
		}
	}
}

// Remove a single item by index s from a slice
func removeFromSlice[T interface{}](slice []T, s int) []T {
	return append(slice[:s], slice[s+1:]...)
}

var errNilProperties = fmt.Errorf("scanner java: properties are nil")

// Recursively get all comma-separated values of the property key. Recursion is necessary since values can include "include" directives which refer to other properties and include them in this property.
func (javaSecurity *JavaSecurity) getPropertyValues(key string) (values []string, err error) {
	if javaSecurity.Properties == nil {
		slog.Info("Could")
		return values, errNilProperties
	}

	fullString, ok := javaSecurity.Get(key)
	if ok {
		values = strings.Split(fullString, ",")
		for i, value := range values {
			values[i] = strings.TrimSpace(value)
		}
	}
	toBeRemoved := []int{} // Remember the include directives and remove them later
	for i, value := range values {
		if strings.HasPrefix(value, "include") {
			toBeRemoved = append(toBeRemoved, i)
			split := strings.Split(value, " ")
			if len(split) > 1 {
				includedValues, err := javaSecurity.getPropertyValues(split[1])
				if err != nil {
					return includedValues, err
				}
				values = append(values, includedValues...)
			}
		}
	}
	for _, remove := range toBeRemoved {
		values = removeFromSlice(values, remove)
	}
	return values, nil
}

// Parses the TLS Rules from the java.security file
// Returns a joined list of errors which occurred during parsing of algorithms
func (javaSecurity *JavaSecurity) extractTLSRules() (err error) {
	slog.Info("Extracting TLS rules", "javaSecurity", javaSecurity)

	securityPropertiesKey := "jdk.tls.disabledAlgorithms"
	algorithms, err := javaSecurity.getPropertyValues(securityPropertiesKey)

	if go_errors.Is(err, errNilProperties) {
		slog.Warn("Properties of javaSecurity object are nil. This should not happen. Continuing anyway.", "JavaSecurity", javaSecurity)
	} else if err != nil {
		return err
	}

	var algorithmParsingErrors []error

	if len(algorithms) > 0 {
		for _, algorithm := range algorithms {
			keySize := 0
			keySizeOperator := keySizeOperatorNone
			name := algorithm

			// TODO: Include directives other than "keySize" (see java.security for reference) --> "usage" is probably the most important one
			if strings.Contains(algorithm, "jdkCA") ||
				strings.Contains(algorithm, "denyAfter") ||
				strings.Contains(algorithm, "usage") {
				slog.Warn("found constraint in java.security that is not supported in this version of CICS", "algorithm", algorithm)
				continue
			}

			if strings.Contains(algorithm, "keySize") {
				split := strings.Split(algorithm, "keySize")
				if len(split) > 2 {
					algorithmParsingErrors = append(algorithmParsingErrors,
						fmt.Errorf("scanner java: sanity check failed, %v contains too many elements (%v)", split, algorithm))
					continue
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
					algorithmParsingErrors = append(algorithmParsingErrors,
						fmt.Errorf("scanner java: could not parse the following keySizeOperator %v (%v)", keyRestrictions[0], algorithm))
					continue
				}

				keySize, err = strconv.Atoi(keyRestrictions[1])
				if err != nil {
					algorithmParsingErrors = append(algorithmParsingErrors,
						fmt.Errorf("scanner java: (%v) %w", algorithm, err))
					continue
				}
			}

			javaSecurity.tlsDisablesAlgorithms = append(javaSecurity.tlsDisablesAlgorithms, JavaSecurityAlgorithmRestriction{
				name:            name,
				keySize:         keySize,
				keySizeOperator: keySizeOperator,
			})
		}
	} else {
		slog.Info("No disabled algorithms specified!", "key", securityPropertiesKey)
	}

	return go_errors.Join(algorithmParsingErrors...)
}

func getUsageCountOfBomRefInSliceOfComponents(components []cdx.Component, bomRef string) (int, error) {
	tempBom := cdx.NewBOM()
	tempBom.Components = new([]cdx.Component)
	*tempBom.Components = append(*tempBom.Components, components...)

	tempTarget, err := os.CreateTemp("", "doComponentsContainBomRef")
	if err != nil {
		return 0, err
	}
	defer os.Remove(tempTarget.Name())

	cyclonedx.WriteBOM(tempBom, tempTarget)

	searchable, err := os.ReadFile(tempTarget.Name())

	if err != nil {
		return 0, err
	}

	return strings.Count(string(searchable), bomRef), nil
}

/*
=======
container image related
=======
*/

const SECURITY_CMD_ARGUMENT = "-Djava.security.properties="

// Tries to get a config from the filesystem and checks the Config for potentially relevant information
func (javaSecurityPlugin *JavaSecurityPlugin) checkConfig() error {
	slog.Info("Checking filesystem config for additional security properties")

	config, ok := javaSecurityPlugin.filesystem.GetConfig()
	if !ok {
		slog.Info("Filesystem did not provide a config. This can be normal if the specified filesystem is not a docker image layer.", "filesystem", javaSecurityPlugin.filesystem)
		return nil
	}

	err := javaSecurityPlugin.checkForAdditionalSecurityFilesCMDParameter(config)

	if go_errors.Is(err, errNilProperties) {
		slog.Warn("Properties of javaSecurity object are nil. This should not happen. Continuing anyway.", "JavaSecurity", javaSecurityPlugin.security)
		return nil
	}

	return err
}

// Searches the image config for potentially relevant CMD parameters and potentially adds new properties
func (javaSecurityPlugin *JavaSecurityPlugin) checkForAdditionalSecurityFilesCMDParameter(config v1.Config) (err error) {
	// We have to check if adding additional security files via CMD is even allowed via the java.security file (security.overridePropertiesFile property)

	if javaSecurityPlugin.security.Properties == nil { // We do not have a security file
		return errNilProperties
	}

	allowAdditionalFiles := javaSecurityPlugin.security.GetBool("security.overridePropertiesFile", true)
	if !allowAdditionalFiles {
		slog.Info("Security properties don't allow additional security files. Stopping searching directly.", "javaSecurity", javaSecurityPlugin.security)
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
			slog.Info("Found command that specifies new properties", "command", command)
			if override {
				slog.Info("Overriding properties with empty object")
				javaSecurityPlugin.security = JavaSecurity{
					properties.NewProperties(), // We override the current loaded property file with an empty object
					javaSecurityPlugin.security.bomRefMap,
					javaSecurityPlugin.security.tlsDisablesAlgorithms,
				}
			}

			content, err := javaSecurityPlugin.filesystem.ReadFile(value)
			if err != nil {
				if strings.Contains(err.Error(), "could not find file path in Tree") {
					slog.Info("failed to read file specified via a command flag in the image configuration (e.g. Dockerfile); the image or image config is probably malformed; continuing without adding it.", "file", value)
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

// Tries to extract the value of a flag in command;
// returns ok if found; returns overwrite if double equals signs were used (==)
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
