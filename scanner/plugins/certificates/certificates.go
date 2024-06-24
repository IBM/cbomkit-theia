package certificates

import (
	"crypto/x509"
	"encoding/pem"
	"ibm/container_cryptography_scanner/provider/filesystem"
	"log/slog"
	"path/filepath"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type CertificatesPlugin struct {
	filesystem filesystem.Filesystem
}

func (certificatesPlugin *CertificatesPlugin) GetName() string {
	return "File Scanning Plugin"
}

func (certificatesPlugin *CertificatesPlugin) walkDirFunc(path string) (err error) {
	var contentASN1DER []byte

	switch filepath.Ext(path) {
	case ".pem":
		pemRaw, err := certificatesPlugin.filesystem.ReadFile(path)
		if err != nil {
			return err
		}
		block, rest := pem.Decode(pemRaw) // TODO: Account for more than one block in file or malformed

		if slices.Equal(rest, pemRaw) {
			slog.Info("Failed to decode pem file, probably malformed. Continuing anyway.")
			return err
		}

		contentASN1DER = block.Bytes

	default:
		return err
	}

	cert, err := x509.ParseCertificate(contentASN1DER)
	if err != nil {
		return err
	}

	print(cert.Issuer.String())

	return err
}

func (certificatesPlugin *CertificatesPlugin) ParseRelevantFilesFromFilesystem(filesystem filesystem.Filesystem) error {
	certificatesPlugin.filesystem = filesystem
	return filesystem.WalkDir(certificatesPlugin.walkDirFunc)
}

func (certificatesPlugin *CertificatesPlugin) UpdateComponents(components []cdx.Component) (updatedComponents []cdx.Component, err error) {
	return components, nil
}
