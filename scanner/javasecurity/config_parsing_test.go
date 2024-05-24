package javasecurity

import (
	"ibm/container_cryptography_scanner/provider/docker"
	"os"
	"strconv"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"

	"gopkg.in/ini.v1"
)

func setUpCMD(originalKey string, originalValue string, newKey string, newValue string, dockerArgument string, dockerCommand string, securityOverridePropertiesFileValue bool) (JavaSecurityPlugin, []string) {
	filesystem, err := os.MkdirTemp("", "CICS_CMD_ARGUMENT_TEST")
	if err != nil {
		panic(err)
	}

	content := []byte{}
	if newKey != "" && newValue != "" {
		content = []byte(newKey + "=" + newValue + "\n")
	}
	additionalFilePath := filesystem + "/test.security"
	err = os.WriteFile(additionalFilePath, content, 0644)
	if err != nil {
		panic(err)
	}

	standardContent := "security.overridePropertiesFile=" + string(strconv.FormatBool(securityOverridePropertiesFileValue)) + "\n"
	if originalKey != "" && originalValue != "" {
		standardContent += originalKey + "=" + originalValue + "\n"
	}
	securityFile := filesystem + "/java.security"
	err = os.WriteFile(securityFile, []byte(standardContent), 0644)
	if err != nil {
		panic(err)
	}

	dockerfile, err := os.CreateTemp("", "CICS_CMD_ARGUMENT_TEST")
	if err != nil {
		panic(err)
	}

	dockercontent := []byte(
		"FROM scratch\n" +
			dockerCommand + " [\"bash\", \"-c\", \"java " + dockerArgument +
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

	filesToDelete := []string{filesystem, dockerfile.Name()}

	return javaSecurityPlugin, filesToDelete
}

func tearDown(filesToDelete []string) {
	for _, file := range filesToDelete {
		os.RemoveAll(file)
	}
}

func TestCMDArgumentAdditionalCMD(t *testing.T) {
	javaSecurityPlugin, filesToDelete := setUpCMD("originalkey", "originalvalue", "mynewtestproperty", "mynewtestvalue", "-Djava.security.properties=", "CMD", true)

	t.Run("Additional java.security files via CMD", func(t *testing.T) {

		err := javaSecurityPlugin.checkDockerfile()
		assert.NoError(t, err, "checkDockerfile failed")

		assert.True(t, javaSecurityPlugin.security.Section("").HasKey("mynewtestproperty"))
		assert.True(t, javaSecurityPlugin.security.Section("").HasKey("originalkey"))
		assert.True(t, javaSecurityPlugin.security.Section("").Key("originalkey").String() == "originalvalue")
		assert.True(t, javaSecurityPlugin.security.Section("").Key("mynewtestproperty").String() == "mynewtestvalue")
	})

	tearDown(filesToDelete)
}

func TestCMDArgumentAdditionalENTRYPOINT(t *testing.T) {
	javaSecurityPlugin, filesToDelete := setUpCMD("originalkey", "originalvalue", "mynewtestproperty", "mynewtestvalue", "-Djava.security.properties=", "ENTRYPOINT", true)

	t.Run("Additional java.security files via CMD", func(t *testing.T) {

		err := javaSecurityPlugin.checkDockerfile()
		assert.NoError(t, err, "checkDockerfile failed")

		assert.True(t, javaSecurityPlugin.security.Section("").HasKey("mynewtestproperty"))
		assert.True(t, javaSecurityPlugin.security.Section("").HasKey("originalkey"))
		assert.True(t, javaSecurityPlugin.security.Section("").Key("originalkey").String() == "originalvalue")
		assert.True(t, javaSecurityPlugin.security.Section("").Key("mynewtestproperty").String() == "mynewtestvalue")
	})

	tearDown(filesToDelete)
}

func TestCMDArgumentOverride(t *testing.T) {
	javaSecurityPlugin, filesToDelete := setUpCMD("mynewtestproperty", "THISSHOULDNOTBEHERE", "mynewtestproperty", "mynewtestvalue", "-Djava.security.properties==", "CMD", true)

	t.Run("Additional java.security files via CMD", func(t *testing.T) {

		err := javaSecurityPlugin.checkDockerfile()
		assert.NoError(t, err, "checkDockerfile failed")

		assert.True(t, javaSecurityPlugin.security.Section("").HasKey("mynewtestproperty"))
		assert.False(t, javaSecurityPlugin.security.Section("").Key("mynewtestproperty").String() == "THISSHOULDNOTBEHERE")
		assert.True(t, javaSecurityPlugin.security.Section("").Key("mynewtestproperty").String() == "mynewtestvalue")
	})

	tearDown(filesToDelete)
}

func TestCMDArgumentNoArgument(t *testing.T) {
	javaSecurityPlugin, filesToDelete := setUpCMD("mynewtestproperty", "THISSHOULDNOTBEHERE", "mynewtestproperty", "mynewtestvalue", "", "CMD", true)

	t.Run("Additional java.security files via CMD", func(t *testing.T) {

		err := javaSecurityPlugin.checkDockerfile()
		assert.NoError(t, err, "checkDockerfile failed")

		assert.True(t, javaSecurityPlugin.security.Section("").HasKey("mynewtestproperty"))
		assert.True(t, javaSecurityPlugin.security.Section("").Key("mynewtestproperty").String() == "THISSHOULDNOTBEHERE")
		assert.False(t, javaSecurityPlugin.security.Section("").Key("mynewtestproperty").String() == "mynewtestvalue")
	})

	tearDown(filesToDelete)
}

func TestCMDArgumentNotAllowed(t *testing.T) {
	javaSecurityPlugin, filesToDelete := setUpCMD("mynewtestproperty", "THISSHOULDNOTBEHERE", "mynewtestproperty", "mynewtestvalue", "-Djava.security.properties==", "CMD", false)

	t.Run("Additional java.security files via CMD", func(t *testing.T) {

		err := javaSecurityPlugin.checkDockerfile()
		assert.NoError(t, err, "checkDockerfile failed")

		assert.True(t, javaSecurityPlugin.security.Section("").HasKey("mynewtestproperty"))
		assert.True(t, javaSecurityPlugin.security.Section("").Key("mynewtestproperty").String() == "THISSHOULDNOTBEHERE")
		assert.False(t, javaSecurityPlugin.security.Section("").Key("mynewtestproperty").String() == "mynewtestvalue")
	})

	tearDown(filesToDelete)
}
