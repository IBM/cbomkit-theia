package javasecurity

import (
	"fmt"
	"ibm/container_cryptography_scanner/provider/docker"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"gopkg.in/ini.v1"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type JavaSecurityPlugin struct {
	security       JavaSecurity
	scannableImage docker.ScannableImage
}

type JavaSecurity struct {
	*ini.File
	tlsDisablesAlgorithms []JavaSecurityAlgorithmRestriction
}

type JavaSecurityAlgorithmRestriction struct {
	name            string
	keySizeOperator string
	keySize         int
}

func (javaSecurityPlugin *JavaSecurityPlugin) GetName() string {
	return "JavaSecurity Policy File"
}

func (javaSecurityPlugin *JavaSecurityPlugin) ParseConfigsFromFilesystem(scannableImage docker.ScannableImage) (err error) {
	javaSecurityPlugin.scannableImage = scannableImage

	err = filepath.WalkDir(scannableImage.Filesystem.Path, javaSecurityPlugin.configWalkDirFunc)
	if err != nil {
		return err
	}

	javaSecurityPlugin.checkDockerfile()

	err = javaSecurityPlugin.extractTLSRules()
	if err != nil {
		return err
	}

	return err
}

func (javaSecurityPlugin *JavaSecurityPlugin) UpdateComponents(components []cdx.Component) (updatedComponents []cdx.Component, err error) {
	for _, component := range components {
		if component.Type == cdx.ComponentTypeCryptographicAsset && component.CryptoProperties != nil {
			updatedComponent, err := javaSecurityPlugin.updateComponent(component)

			if err != nil {
				return nil, err
			}

			if updatedComponent == nil {
				continue
			} else {
				updatedComponents = append(updatedComponents, *updatedComponent)
			}
		}
	}
	return updatedComponents, err
}

// Internal
func (javaSecurityAlgorithmRestriction JavaSecurityAlgorithmRestriction) eval(component cdx.Component) (allowed bool, err error) {
	allowed = true

	if component.CryptoProperties.AssetType != cdx.CryptoAssetTypeAlgorithm {
		return allowed, fmt.Errorf("scanner: cannot evaluate components other than algorithm for applying restrictions")
	}

	subAlgorithms := strings.Split(component.Name, "with")

	for _, subAlgorithm := range subAlgorithms {
		if subAlgorithm == component.Name {
			param, err := strconv.Atoi(component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier)
			if err != nil {
				return allowed, err
			}
			switch javaSecurityAlgorithmRestriction.keySizeOperator {
			case "<=":
				allowed = !(param <= javaSecurityAlgorithmRestriction.keySize)
			case "<":
				allowed = !(param < javaSecurityAlgorithmRestriction.keySize)
			case "==":
				allowed = !(param == javaSecurityAlgorithmRestriction.keySize)
			case "!=":
				allowed = !(param != javaSecurityAlgorithmRestriction.keySize)
			case ">=":
				allowed = !(param >= javaSecurityAlgorithmRestriction.keySize)
			case ">":
				allowed = !(param > javaSecurityAlgorithmRestriction.keySize)
			default:
				return allowed, fmt.Errorf("scanner: invalid keySizeOperator in JavaSecurityAlgorithmRestriction")
			}
		}

		if !allowed {
			return allowed, err
		}
	}

	return allowed, err
}

func (javaSecurityPlugin *JavaSecurityPlugin) extractTLSRules() (err error) {
	if javaSecurityPlugin.security.Section("").HasKey("jdk.tls.disabledAlgorithms") {
		algorithms := javaSecurityPlugin.security.Section("").Key("jdk.tls.disabledAlgorithms").Strings(",")
		for _, algorithm := range algorithms {
			keySize := 0
			keySizeOperator := ""
			name := algorithm

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

			javaSecurityPlugin.security.tlsDisablesAlgorithms = append(javaSecurityPlugin.security.tlsDisablesAlgorithms, JavaSecurityAlgorithmRestriction{
				name:            name,
				keySize:         keySize,
				keySizeOperator: keySizeOperator,
			})
		}
	}

	return nil
}

func (javaSecurityPlugin *JavaSecurityPlugin) isComponentAffectedByConfig(component cdx.Component) bool {
	// First we need to assess if the component is even from a source affected by this type of config (e.g. a java file)

	if component.Evidence.Occurrences == nil { // If there is no evidence telling us that whether this component comes from a python file, we cannot assess it
		return false
	}

	for _, occurrence := range *component.Evidence.Occurrences {
		if filepath.Ext(occurrence.Location) == ".java" {
			return true
		}
	}

	// TODO: Check if security property were changed dynamically

	return false
}

func (javaSecurityPlugin *JavaSecurityPlugin) updateProtocolComponent(component cdx.Component) (updatedComponent *cdx.Component, err error) {
	if component.CryptoProperties.AssetType != cdx.CryptoAssetTypeProtocol {
		return &component, fmt.Errorf("scanner: component of type %v cannot be used in function updateProtocolComponent", component.CryptoProperties.AssetType)
	}

	switch component.CryptoProperties.ProtocolProperties.Type {
	case cdx.CryptoProtocolTypeTLS:
		for _, cipherSuites := range *component.CryptoProperties.ProtocolProperties.CipherSuites {
			for algorithmRef := range *cipherSuites.Algorithms {
				// TODO: Dereference Algorithm REFs and extract algorithm objects
				log.Default().Printf("Found algorithmRef: %v", algorithmRef)
			}
		}
	default:
		return &component, nil
	}

	return &component, nil
}

func (javaSecurityPlugin *JavaSecurityPlugin) updateComponent(component cdx.Component) (updatedComponent *cdx.Component, err error) {

	if !javaSecurityPlugin.isComponentAffectedByConfig(component) {
		return &component, nil
	}

	log.Default().Printf("Detected %v", component.CryptoProperties.AssetType)

	switch component.CryptoProperties.AssetType {
	case cdx.CryptoAssetTypeProtocol:
		return javaSecurityPlugin.updateProtocolComponent(component)
	default:
		return &component, nil
	}

	// log.Default().Printf("The following component is not valid due to %v config:\n%+v", javaSecurityPlugin.GetName(), component)
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
	// By now, the docker package should have validated the correctness of the file

	if len(stages) < 1 { // This Dockerfile is empty
		return
	}

	// TODO: Check for relevant parameters here

}

func (javaSecurityPlugin *JavaSecurityPlugin) isConfigFile(path string) bool {
	// Check if this file is the java.security file and if that is the case extract the path of the active crypto.policy files
	ext := filepath.Ext(path)
	return ext == ".security"
}

func (javaSecurityPlugin *JavaSecurityPlugin) configWalkDirFunc(path string, d fs.DirEntry, err error) error {
	if d.IsDir() {
		return nil
	}

	if javaSecurityPlugin.isConfigFile(path) {
		var config *ini.File
		config, err = ini.Load(path)
		javaSecurityPlugin.security = JavaSecurity{
			config,
			[]JavaSecurityAlgorithmRestriction{},
		}
	}

	return err
}
