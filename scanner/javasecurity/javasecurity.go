package javasecurity

import (
	"ibm/container_cryptography_scanner/provider/docker"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"gopkg.in/ini.v1"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type JavaSecurityPlugin struct {
	security       *ini.File
	scannableImage docker.ScannableImage
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
func (javaSecurityPlugin *JavaSecurityPlugin) updateComponent(component cdx.Component) (updatedComponent *cdx.Component, err error) {

	// log.Default().Printf("The following component is not valid due to %v config:\n%+v", javaSecurityPlugin.GetName(), component)
	return nil, err
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
		javaSecurityPlugin.security, err = ini.Load(path)
	}

	return err
}
