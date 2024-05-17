package javasecurity

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/ini.v1"

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
func (javaSecurityPlugin *JavaSecurityPlugin) configWalkDirFunc(path string, d fs.DirEntry, err error) error {
	if d.IsDir() {
		return nil
	}

	if javaSecurityPlugin.isConfigFile(path) {
		var config *ini.File
		config, err = ini.Load(path)
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
	*ini.File
	bomRefMap             map[cdx.BOMReference]*cdx.Component
	tlsDisablesAlgorithms []JavaSecurityAlgorithmRestriction
}

// Creates a map from BOMReferences to Components to allow for fast reference
func (javaSecurity *JavaSecurity) createCryptoComponentBOMRefMap(components []cdx.Component) {
	for _, component := range components {
		if component.BOMRef != "" {
			javaSecurity.bomRefMap[cdx.BOMReference(component.BOMRef)] = &component
		}
	}
}

// Parses the TLS Rules from the java.security file
func (javaSecurity *JavaSecurity) extractTLSRules() (err error) {
	if javaSecurity.Section("").HasKey("jdk.tls.disabledAlgorithms") {
		algorithms := javaSecurity.Section("").Key("jdk.tls.disabledAlgorithms").Strings(",")
		for _, algorithm := range algorithms {
			keySize := 0
			keySizeOperator := ""
			name := algorithm

			// TODO: Include directives other than "keySize" (see java.security for reference)
			if strings.Contains(algorithm, "keySize") {
				split := strings.Split(algorithm, "keySize")
				if len(split) > 2 {
					return fmt.Errorf("scanner: sanity check failed, %v contains too many elements", split)
				}
				name = strings.TrimSpace(split[0])
				split[1] = strings.TrimSpace(split[1])
				keyRestrictions := strings.Split(split[1], " ")
				keySizeOperator = keyRestrictions[0]
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

// Checks the Dockerfile for potentially relevant information and adds it to the plugin
// THIS FUNCTION IS CURRENTLY DOING NOTHING
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
	// By now, the docker package should have validated the correctness of the file

	if len(stages) < 1 { // This Dockerfile is empty
		return
	}

	// TODO: Check for relevant parameters here

}