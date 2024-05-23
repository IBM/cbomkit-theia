package javasecurity

import (
	"ibm/container_cryptography_scanner/provider/docker"
	"os"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"

	"gopkg.in/ini.v1"
)

func TestCMDArgument(t *testing.T) {
	t.Run("Additional java.security files via CMD", func(t *testing.T) {
		filesystem, err := os.MkdirTemp("", "CICS_CMD_ARGUMENT_TEST")
		if err != nil {
			panic(err)
		}

		content := []byte("mynewtestproperty=mynewtestvalue\n")
		additionalFilePath := filesystem + "/test.security"
		err = os.WriteFile(additionalFilePath, content, 0644)
		if err != nil {
			panic(err)
		}

		standardContent := []byte("security.overridePropertiesFile=true\n")
		securityFile := filesystem + "/java.security"
		err = os.WriteFile(securityFile, standardContent, 0644)
		if err != nil {
			panic(err)
		}

		dockerfile, err := os.CreateTemp("", "CICS_CMD_ARGUMENT_TEST")
		if err != nil {
			panic(err)
		}

		dockercontent := []byte(
			"FROM scratch\n" +
				"CMD [\"bash\", \"-c\", \"java -Djava.security.properties=" +
				additionalFilePath +
				" RemoteRMIServer\"\n")

		err = os.WriteFile(dockerfile.Name(), dockercontent, 0644)
		if err != nil {
			panic(err)
		}

		ini, err := ini.Load(securityFile)
		if err != nil {
			panic(err)
		}

		javaSecurityPlugin := JavaSecurityPlugin{
			security: JavaSecurity{
				ini,
				map[cdx.BOMReference]*cdx.Component{},
				[]JavaSecurityAlgorithmRestriction{},
			},
			scannableImage: docker.ScannableImage{
				Filesystem: docker.Filesystem{
					Path: filesystem,
				},
				DockerfilePath: dockerfile.Name(),
			},
		}

		err = javaSecurityPlugin.checkDockerfile()
		assert.NoError(t, err, "checkDockerfile failed")

		assert.True(t, javaSecurityPlugin.security.Section("").HasKey("mynewtestproperty"))
		assert.True(t, javaSecurityPlugin.security.Section("").Key("mynewtestproperty").String() == "mynewtestvalue")

		os.RemoveAll(filesystem)
		os.Remove(dockerfile.Name())
	})
}
