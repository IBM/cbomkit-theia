package certificates

import (
	"encoding/pem"
	"errors"
	"ibm/container_cryptography_scanner/provider/filesystem"
	scanner_errors "ibm/container_cryptography_scanner/scanner/errors"
	"log/slog"
	"path/filepath"

	"go.mozilla.org/pkcs7" // TODO: Deprecated -> Replace

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type CertificatesPlugin struct {
	filesystem filesystem.Filesystem
	certs      []*X509CertificateWithMetadata
}

func (certificatesPlugin *CertificatesPlugin) GetName() string {
	return "Certificate File Plugin"
}

func (certificatesPlugin *CertificatesPlugin) walkDirFunc(path string) (err error) {
	switch filepath.Ext(path) {
	case ".pem", ".cer", ".cert", ".der", ".ca-bundle", ".crt":
		certs, err := certificatesPlugin.parsex509CertFromPath(path)
		if err != nil {
			return scanner_errors.GetParsingFailedAlthoughCheckedError(err, certificatesPlugin.GetName())
		}
		certificatesPlugin.certs = append(certificatesPlugin.certs, certs...)
	case ".p7a", ".p7b", ".p7c", ".p7r", ".p7s", ".spc":
		certs, err := certificatesPlugin.parsePKCS7FromPath(path)
		if err != nil {
			return scanner_errors.GetParsingFailedAlthoughCheckedError(err, certificatesPlugin.GetName())
		}
		certificatesPlugin.certs = append(certificatesPlugin.certs, certs...)
	default:
		return err
	}

	return err
}

func (certificatesPlugin *CertificatesPlugin) parsex509CertFromPath(path string) ([]*X509CertificateWithMetadata, error) {
	rawFileBytes, err := certificatesPlugin.filesystem.ReadFile(path)

	if err != nil {
		return make([]*X509CertificateWithMetadata, 0), nil
	}

	rest := rawFileBytes
	var blocks []*pem.Block
	for len(rest) != 0 {
		var newBlock *pem.Block
		newBlock, rest = pem.Decode(rest)
		if newBlock != nil {
			if newBlock.Type != "CERTIFICATE" {
				slog.Warn("PEM file contains part that is not yet supported, continuing anyway", "unsupported_type", newBlock.Type)
				continue
			}
			blocks = append(blocks, newBlock)
		} else {
			break
		}
	}

	if len(blocks) == 0 {
		return ParseCertificatesToX509CertificateWithMetadata(rawFileBytes, path)
	}

	certs := make([]*X509CertificateWithMetadata, 0, len(blocks))

	for _, block := range blocks {
		moreCerts, err := ParseCertificatesToX509CertificateWithMetadata(block.Bytes, path)
		if err != nil {
			return moreCerts, err
		}
		certs = append(certs, moreCerts...)
	}

	return certs, err
}

func (certificatesPlugin CertificatesPlugin) parsePKCS7FromPath(path string) ([]*X509CertificateWithMetadata, error) {
	raw, err := certificatesPlugin.filesystem.ReadFile(path)
	if err != nil {
		return make([]*X509CertificateWithMetadata, 0), err
	}

	block, _ := pem.Decode(raw)

	pkcs7Object, err := pkcs7.Parse(block.Bytes)
	if err != nil || pkcs7Object == nil {
		return make([]*X509CertificateWithMetadata, 0), err
	}

	certsWithMetadata := make([]*X509CertificateWithMetadata, 0, len(pkcs7Object.Certificates))

	for _, cert := range pkcs7Object.Certificates {
		certWithMetadata, err := NewX509CertificateWithMetadata(cert, path)
		if err != nil {
			return make([]*X509CertificateWithMetadata, 0), err
		}
		certsWithMetadata = append(certsWithMetadata, certWithMetadata)
	}

	return certsWithMetadata, nil
}

func (certificatesPlugin *CertificatesPlugin) ParseRelevantFilesFromFilesystem(filesystem filesystem.Filesystem) error {
	certificatesPlugin.filesystem = filesystem
	err := filesystem.WalkDir(certificatesPlugin.walkDirFunc)
	slog.Info("Certificate searching done", "count", len(certificatesPlugin.certs))
	return err
}

func (certificatesPlugin *CertificatesPlugin) UpdateComponents(components []cdx.Component) (updatedComponents []cdx.Component, err error) {
	for _, cert := range certificatesPlugin.certs {
		cdxComps, err := cert.GenerateCDXComponents()
		if errors.Is(err, ErrX509UnknownAlgorithm) {
			slog.Info("X.509 certs contained unknown algorithms. Continuing anyway", "errors", err)
		} else if err != nil {
			return cdxComps, err
		}
		components = append(components, cdxComps...)
	}

	return components, nil
}
