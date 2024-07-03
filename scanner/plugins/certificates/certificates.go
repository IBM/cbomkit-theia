package certificates

import (
	"encoding/pem"
	"errors"
	"ibm/container-image-cryptography-scanner/provider/filesystem"
	scanner_errors "ibm/container-image-cryptography-scanner/scanner/errors"
	"log/slog"
	"path/filepath"
	"slices"

	"go.mozilla.org/pkcs7" // TODO: Deprecated -> Replace
	"golang.org/x/exp/rand"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
)

// Plugin to parse certificates from the filesystem
type CertificatesPlugin struct {
	filesystem filesystem.Filesystem
	certs      []*x509CertificateWithMetadata
}

// Get the name of the plugin
func (certificatesPlugin *CertificatesPlugin) GetName() string {
	return "Certificate File Plugin"
}

// Check every file for a certificate and parse it if possible
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

// Parse a X.509 certificate from the given path (in base64 PEM or binary DER)
func (certificatesPlugin *CertificatesPlugin) parsex509CertFromPath(path string) ([]*x509CertificateWithMetadata, error) {
	rawFileBytes, err := certificatesPlugin.filesystem.ReadFile(path)

	if err != nil {
		return make([]*x509CertificateWithMetadata, 0), nil
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
		return parseCertificatesToX509CertificateWithMetadata(rawFileBytes, path)
	}

	certs := make([]*x509CertificateWithMetadata, 0, len(blocks))

	for _, block := range blocks {
		moreCerts, err := parseCertificatesToX509CertificateWithMetadata(block.Bytes, path)
		if err != nil {
			return moreCerts, err
		}
		certs = append(certs, moreCerts...)
	}

	return certs, err
}

// Parse X.509 certificates from a PKCS7 file (base64 PEM format)
func (certificatesPlugin CertificatesPlugin) parsePKCS7FromPath(path string) ([]*x509CertificateWithMetadata, error) {
	raw, err := certificatesPlugin.filesystem.ReadFile(path)
	if err != nil {
		return make([]*x509CertificateWithMetadata, 0), err
	}

	block, _ := pem.Decode(raw)

	pkcs7Object, err := pkcs7.Parse(block.Bytes)
	if err != nil || pkcs7Object == nil {
		return make([]*x509CertificateWithMetadata, 0), err
	}

	certsWithMetadata := make([]*x509CertificateWithMetadata, 0, len(pkcs7Object.Certificates))

	for _, cert := range pkcs7Object.Certificates {
		certWithMetadata, err := newX509CertificateWithMetadata(cert, path)
		if err != nil {
			return make([]*x509CertificateWithMetadata, 0), err
		}
		certsWithMetadata = append(certsWithMetadata, certWithMetadata)
	}

	return certsWithMetadata, nil
}

// Parse all certificates from the given filesystem
func (certificatesPlugin *CertificatesPlugin) ParseRelevantFilesFromFilesystem(filesystem filesystem.Filesystem) error {
	certificatesPlugin.filesystem = filesystem
	err := filesystem.WalkDir(certificatesPlugin.walkDirFunc)
	slog.Info("Certificate searching done", "count", len(certificatesPlugin.certs))
	return err
}

// Add the found certificates to the slice of components
func (certificatesPlugin *CertificatesPlugin) UpdateComponents(components []cdx.Component) (updatedComponents []cdx.Component, err error) {
	uuid.SetRand(rand.New(rand.NewSource(1)))

	for _, cert := range certificatesPlugin.certs {
		cdxComps, err := cert.generateCDXComponents()
		if errors.Is(err, errX509UnknownAlgorithm) {
			slog.Info("X.509 certs contained unknown algorithms. Continuing anyway", "errors", err)
		} else if err != nil {
			return cdxComps, err
		}
		components = append(components, cdxComps...)
	}

	// Removing all duplicates
	uniqueComponents := make([]cdx.Component, 0)
	bomRefsToReplace := make(map[cdx.BOMReference]cdx.BOMReference)
	for _, comp := range components {
		if comp.CryptoProperties.AssetType != cdx.CryptoAssetTypeAlgorithm {
			uniqueComponents = append(uniqueComponents, comp)
			continue
		}
		contains, collider := strippedAlgorithmContains(comp, uniqueComponents)
		if !contains {
			uniqueComponents = append(uniqueComponents, comp)
		} else {
			bomRefsToReplace[cdx.BOMReference(comp.BOMRef)] = cdx.BOMReference(collider.BOMRef)
		}
	}

	for oldRef, newRef := range bomRefsToReplace {
		replaceBomRefUsages(oldRef, newRef, &uniqueComponents)
	}

	return uniqueComponents, nil
}

// Check if comp is contained in list while ignoring BOMReferences
func strippedAlgorithmContains(comp cdx.Component, list []cdx.Component) (bool, cdx.Component) {
	if comp.CryptoProperties.AssetType != cdx.CryptoAssetTypeAlgorithm {
		panic("scanner: strippedAlgorithmContains was called on a non-algorithm component")
	}
	for _, comp2 := range list {
		if comp2.CryptoProperties.AssetType == cdx.CryptoAssetTypeAlgorithm && strippedAlgorithmEquals(comp, comp2) {
			return true, comp2
		}
	}

	return false, cdx.Component{}
}

// Check if a equals b while ignoring BOMReferences
func strippedAlgorithmEquals(a cdx.Component, b cdx.Component) bool {
	if a.CryptoProperties.AssetType != cdx.CryptoAssetTypeAlgorithm || b.CryptoProperties.AssetType != cdx.CryptoAssetTypeAlgorithm {
		panic("scanner: strippedAlgorithmEquals was called on a non-algorithm component")
	}

	return a.Name == b.Name &&
		a.CryptoProperties.AlgorithmProperties.Primitive == b.CryptoProperties.AlgorithmProperties.Primitive &&
		a.CryptoProperties.AlgorithmProperties.ExecutionEnvironment == b.CryptoProperties.AlgorithmProperties.ExecutionEnvironment &&
		a.CryptoProperties.AlgorithmProperties.ImplementationPlatform == b.CryptoProperties.AlgorithmProperties.ImplementationPlatform &&
		slices.Equal(*a.CryptoProperties.AlgorithmProperties.CertificationLevel, *b.CryptoProperties.AlgorithmProperties.CertificationLevel) &&
		slices.Equal(*a.CryptoProperties.AlgorithmProperties.CryptoFunctions, *b.CryptoProperties.AlgorithmProperties.CryptoFunctions) &&
		a.CryptoProperties.OID == b.CryptoProperties.OID &&
		a.CryptoProperties.AlgorithmProperties.Padding == b.CryptoProperties.AlgorithmProperties.Padding
}

// Replace all usages of oldRef by newRef in components
func replaceBomRefUsages(oldRef cdx.BOMReference, newRef cdx.BOMReference, components *[]cdx.Component) {
	for _, comp := range *components {
		if comp.BOMRef == string(oldRef) {
			comp.BOMRef = string(newRef)
		}

		if comp.CryptoProperties != nil {
			if comp.CryptoProperties.CertificateProperties != nil {
				if comp.CryptoProperties.CertificateProperties.SignatureAlgorithmRef == oldRef {
					comp.CryptoProperties.CertificateProperties.SignatureAlgorithmRef = newRef
					continue
				}
				if comp.CryptoProperties.CertificateProperties.SubjectPublicKeyRef == oldRef {
					comp.CryptoProperties.CertificateProperties.SubjectPublicKeyRef = newRef
					continue
				}
			} else if comp.CryptoProperties.RelatedCryptoMaterialProperties != nil {
				if comp.CryptoProperties.RelatedCryptoMaterialProperties.AlgorithmRef == oldRef {
					comp.CryptoProperties.RelatedCryptoMaterialProperties.AlgorithmRef = newRef
					continue
				}
			}
		}
	}
}
