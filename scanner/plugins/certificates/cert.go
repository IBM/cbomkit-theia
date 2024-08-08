package certificates

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	bomdag "ibm/container-image-cryptography-scanner/scanner/bom-dag"

	"github.com/google/uuid"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// A X.509 certificate with additional metadata that is not part of the x509.Certificate struct
type x509CertificateWithMetadata struct {
	*x509.Certificate
	path   string
	format string
}

// During parsing of the x509.Certificate a unknown algorithm was found
var errX509UnknownAlgorithm = errors.New("X.509 certificate has unknown algorithm")

// Create a new x509CertificateWithMetadata from a x509.Certificate and a path
func newX509CertificateWithMetadata(cert *x509.Certificate, path string) (*x509CertificateWithMetadata, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}
	return &x509CertificateWithMetadata{
		cert,
		path,
		"X.509",
	}, nil
}

// Convenience function to parse der bytes into a slice of x509CertificateWithMetadata
func parseCertificatesToX509CertificateWithMetadata(der []byte, path string) ([]*x509CertificateWithMetadata, error) {
	certs, err := x509.ParseCertificates(der)
	if err != nil {
		return make([]*x509CertificateWithMetadata, 0), err
	}

	certsWithMetadata := make([]*x509CertificateWithMetadata, 0, len(certs))

	for _, cert := range certs {
		certWithMetadata, err := newX509CertificateWithMetadata(cert, path)
		if err != nil {
			return certsWithMetadata, err
		}
		certsWithMetadata = append(certsWithMetadata, certWithMetadata)
	}

	return certsWithMetadata, err
}

func (x509CertificateWithMetadata *x509CertificateWithMetadata) generateDAG() (bomdag.BomDAG, error) {
	dag := bomdag.NewBomDAG()

	// Creating BOM Components
	certificate := x509CertificateWithMetadata.getCertificateComponent()
	signatureAlgorithm, err1 := x509CertificateWithMetadata.getSignatureAlgorithmComponent()
	publicKeyAlgorithm, err2 := x509CertificateWithMetadata.getPublicKeyAlgorithmComponent()
	publicKey, err3 := x509CertificateWithMetadata.getPublicKeyComponent()

	err := errors.Join(err1, err2, err3)
	if err != nil {
		return dag, err
	}

	// Adding BOM Components to DAG
	certificateHash, err1 := dag.AddCDXComponent(certificate)
	publicKeyAlgorithmHash, err2 := dag.AddCDXComponent(publicKeyAlgorithm)
	publicKeyHash, err3 := dag.AddCDXComponent(publicKey)

	var signatureAlgorithmHash, signatureAlgorithmPKEHash, signatureAlgorithmHashHash [32]byte
	var err4, err5, err6 error
	if signatureAlgorithm.signature != nil {
		signatureAlgorithmHash, err4 = dag.AddCDXComponent(*signatureAlgorithm.signature)
	}
	if signatureAlgorithm.pke != nil {
		signatureAlgorithmPKEHash, err5 = dag.AddCDXComponent(*signatureAlgorithm.pke)
	}
	if signatureAlgorithm.hash != nil {
		signatureAlgorithmHashHash, err6 = dag.AddCDXComponent(*signatureAlgorithm.hash)
	}

	err = errors.Join(err1, err2, err3, err4, err5, err6)
	if err != nil {
		return dag, err
	}

	// Creating Edges in DAG
	err6 = dag.AddEdge(dag.Root, certificateHash)
	err1 = dag.AddEdge(certificateHash, publicKeyHash,
		bomdag.EdgeDependencyType(bomdag.BomDAGDependencyTypeCertificatePropertiesSubjectPublicKeyRef))
	err2 = dag.AddEdge(publicKeyHash, publicKeyAlgorithmHash,
		bomdag.EdgeDependencyType(bomdag.BomDAGDependencyTypeRelatedCryptoMaterialPropertiesAlgorithmRef))
	err3 = dag.AddEdge(certificateHash, signatureAlgorithmHash,
		bomdag.EdgeDependencyType(bomdag.BomDAGDependencyTypeCertificatePropertiesSignatureAlgorithmRef))
	err4 = dag.AddEdge(signatureAlgorithmHash, signatureAlgorithmPKEHash,
		bomdag.EdgeDependencyType(bomdag.BomDAGDependencyTypeDependsOn))
	err5 = dag.AddEdge(signatureAlgorithmHash, signatureAlgorithmHashHash,
		bomdag.EdgeDependencyType(bomdag.BomDAGDependencyTypeDependsOn))

	return dag, errors.Join(err1, err2, err3, err4, err5, err6)
}

// Generate CycloneDX components from the x509CertificateWithMetadata (e.g. certificate, signature algorithm, public key and public key algorithm)
func (x509CertificateWithMetadata *x509CertificateWithMetadata) generateCDXComponents() ([]cdx.Component, []cdx.Dependency, error) {
	dag, err := x509CertificateWithMetadata.generateDAG()

	if err != nil {
		return []cdx.Component{}, []cdx.Dependency{}, err
	}

	components, dependencyMap, err := dag.GetCDXComponents()

	return components, dependencyMapToStructSlice(dependencyMap), err
}

// Generate the CycloneDX component for the certificate
func (x509CertificateWithMetadata *x509CertificateWithMetadata) getCertificateComponent() cdx.Component {
	return cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   x509CertificateWithMetadata.Subject.CommonName,
		BOMRef: uuid.New().String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeCertificate,
			CertificateProperties: &cdx.CertificateProperties{
				SubjectName:          x509CertificateWithMetadata.Subject.CommonName,
				IssuerName:           x509CertificateWithMetadata.Issuer.CommonName,
				NotValidBefore:       x509CertificateWithMetadata.NotBefore.Format(time.RFC3339),
				NotValidAfter:        x509CertificateWithMetadata.NotAfter.Format(time.RFC3339),
				CertificateFormat:    x509CertificateWithMetadata.format,
				CertificateExtension: filepath.Ext(x509CertificateWithMetadata.path),
			},
		},
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{
					Location: x509CertificateWithMetadata.path,
				}},
		},
	}
}

type signatureAlgorithmResult struct {
	signature *cdx.Component
	hash      *cdx.Component
	pke       *cdx.Component
}

// Generate the CycloneDX component for the signature algorithm
func (x509CertificateWithMetadata *x509CertificateWithMetadata) getSignatureAlgorithmComponent() (signatureAlgorithmResult, error) {
	switch x509CertificateWithMetadata.SignatureAlgorithm {
	case x509.MD2WithRSA:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		comp.CryptoProperties.OID = "1.3.14.7.2.3.1"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "MD2"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "2"
		hash.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingOther

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "RSA"

		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.MD5WithRSA:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		comp.CryptoProperties.OID = "1.3.14.3.2.3"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "MD5"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "5"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "RSA"

		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.SHA1WithRSA:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "160"
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		comp.CryptoProperties.OID = "1.2.840.113549.1.1.5"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "SHA1"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "1"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "RSA"

		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.SHA256WithRSA:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		comp.CryptoProperties.OID = "1.2.840.113549.1.1.11"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "SHA256"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "RSA"

		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.SHA384WithRSA:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "384"
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		comp.CryptoProperties.OID = "1.2.840.113549.1.1.12"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "SHA384"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "384"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "RSA"

		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.SHA512WithRSA:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "512"
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		comp.CryptoProperties.OID = "1.2.840.113549.1.1.13"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "SHA512"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "512"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "RSA"

		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.DSAWithSHA1:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "160"
		comp.CryptoProperties.OID = "1.3.14.3.2.27"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "SHA1"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "1"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "DSA"

		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.DSAWithSHA256:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"
		comp.CryptoProperties.OID = "2.16.840.1.101.3.4.3.2"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "SHA256"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "DSA"
		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.ECDSAWithSHA1:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "160"
		comp.CryptoProperties.OID = "1.2.840.10045.4.1"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "SHA1"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "1"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "ECDSA"
		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.ECDSAWithSHA256:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"
		comp.CryptoProperties.OID = "1.2.840.10045.4.3.2"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "SHA256"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "ECDSA"
		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.ECDSAWithSHA384:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "384"
		comp.CryptoProperties.OID = "1.2.840.10045.4.3.3"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "SHA384"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "384"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "ECDSA"
		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.ECDSAWithSHA512:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "512"
		comp.CryptoProperties.OID = "1.2.840.10045.4.3.4"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "SHA512"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "512"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "ECDSA"
		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.SHA256WithRSAPSS:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingOther
		comp.CryptoProperties.OID = "1.2.840.113549.1.1.11"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "SHA256"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "RSAPSS"
		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.SHA384WithRSAPSS:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "384"
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingOther
		comp.CryptoProperties.OID = "1.2.840.113549.1.1.12"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "SHA384"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "384"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "RSAPSS"
		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.SHA512WithRSAPSS:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "512"
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingOther
		comp.CryptoProperties.OID = "1.2.840.113549.1.1.13"

		hash := getGenericHashAlgorithmComponent(x509CertificateWithMetadata.path)
		hash.Name = "SHA512"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "512"

		pke := getGenericPKEAlgorithmComponent(x509CertificateWithMetadata.path)
		pke.Name = "RSAPSS"
		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.PureEd25519:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.Curve = "Ed25519"
		comp.CryptoProperties.OID = "1.3.101.112"
		return signatureAlgorithmResult{
			signature: &comp,
			hash:      nil,
			pke:       nil,
		}, nil
	default:
		return signatureAlgorithmResult{
			signature: nil,
			hash:      nil,
			pke:       nil,
		}, errX509UnknownAlgorithm
	}
}

// Generate a generic CycloneDX component for the signature algorithm
func getGenericSignatureAlgorithmComponent(algo x509.SignatureAlgorithm, path string) cdx.Component {
	return cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   algo.String(),
		BOMRef: uuid.New().String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
				Primitive:              cdx.CryptoPrimitiveSignature,
				ExecutionEnvironment:   cdx.CryptoExecutionEnvironmentUnknown,
				ImplementationPlatform: cdx.ImplementationPlatformUnknown,
				CertificationLevel:     &[]cdx.CryptoCertificationLevel{cdx.CryptoCertificationLevelUnknown},
				CryptoFunctions:        &[]cdx.CryptoFunction{cdx.CryptoFunctionSign},
			},
		},
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{
					Location: path,
				}},
		},
	}
}

// Generate a generic CycloneDX component for a hash algorithm
func getGenericHashAlgorithmComponent(path string) cdx.Component {
	return cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		BOMRef: uuid.New().String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
				Primitive:              cdx.CryptoPrimitiveHash,
				ExecutionEnvironment:   cdx.CryptoExecutionEnvironmentUnknown,
				ImplementationPlatform: cdx.ImplementationPlatformUnknown,
				CertificationLevel:     &[]cdx.CryptoCertificationLevel{cdx.CryptoCertificationLevelUnknown},
				CryptoFunctions:        &[]cdx.CryptoFunction{cdx.CryptoFunctionDigest},
			},
		},
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{
					Location: path,
				}},
		},
	}
}

// Generate a generic CycloneDX component for a hash algorithm
func getGenericPKEAlgorithmComponent(path string) cdx.Component {
	return cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		BOMRef: uuid.New().String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
				Primitive:              cdx.CryptoPrimitivePKE,
				ExecutionEnvironment:   cdx.CryptoExecutionEnvironmentUnknown,
				ImplementationPlatform: cdx.ImplementationPlatformUnknown,
				CertificationLevel:     &[]cdx.CryptoCertificationLevel{cdx.CryptoCertificationLevelUnknown},
				CryptoFunctions:        &[]cdx.CryptoFunction{cdx.CryptoFunctionSign},
			},
		},
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{
					Location: path,
				}},
		},
	}
}

// Generate the CycloneDX component for the public key
func (x509CertificateWithMetadata *x509CertificateWithMetadata) getPublicKeyComponent() (cdx.Component, error) {
	switch x509CertificateWithMetadata.PublicKey.(type) {
	case *rsa.PublicKey:
		pk := x509CertificateWithMetadata.PublicKey.(*rsa.PublicKey)
		comp := getGenericPublicKeyComponent(x509CertificateWithMetadata.path, pk)
		size := pk.Size() * 8
		comp.Name = fmt.Sprintf("RSA-%v", size)
		comp.CryptoProperties.RelatedCryptoMaterialProperties.Size = &size
		comp.CryptoProperties.OID = "1.2.840.113549.1.1.1"
		return comp, nil
	case *dsa.PublicKey:
		pk := x509CertificateWithMetadata.PublicKey.(*dsa.PublicKey)
		comp := getGenericPublicKeyComponent(x509CertificateWithMetadata.path, pk)
		comp.Name = "DSA"
		size := pk.Y.BitLen()
		comp.CryptoProperties.RelatedCryptoMaterialProperties.Size = &size
		comp.CryptoProperties.OID = "1.3.14.3.2.12"
		return comp, nil
	case *ecdsa.PublicKey:
		pk := x509CertificateWithMetadata.PublicKey.(*ecdsa.PublicKey)
		comp := getGenericPublicKeyComponent(x509CertificateWithMetadata.path, pk)
		comp.CryptoProperties.OID = "1.2.840.10045.2.1"
		return comp, nil
	case *ed25519.PublicKey:
		pk := x509CertificateWithMetadata.PublicKey.(*ed25519.PublicKey)
		comp := getGenericPublicKeyComponent(x509CertificateWithMetadata.path, *pk)
		comp.Name = "ED25519"
		comp.CryptoProperties.OID = "1.3.101.112"
		return comp, nil
	default:
		return cdx.Component{}, errX509UnknownAlgorithm
	}
}

// Generate a generic CycloneDX component for the public key
func getGenericPublicKeyComponent(path string, key any) cdx.Component {
	comp := cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		BOMRef: uuid.New().String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type: cdx.RelatedCryptoMaterialTypePublicKey,
			},
		},
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{
					Location: path,
				}},
		},
	}

	keyValue, err := x509.MarshalPKIXPublicKey(key)
	if err == nil {
		comp.CryptoProperties.RelatedCryptoMaterialProperties.Value = base64.StdEncoding.EncodeToString(keyValue)
	}

	return comp
}

// Generate the CycloneDX component for the public key algorithm
func (x509CertificateWithMetadata *x509CertificateWithMetadata) getPublicKeyAlgorithmComponent() (cdx.Component, error) {
	switch x509CertificateWithMetadata.PublicKeyAlgorithm {
	case x509.RSA:
		comp := getGenericPublicKeyAlgorithmComponent(x509CertificateWithMetadata.PublicKeyAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.OID = "1.2.840.113549.1.1.1"
		return comp, nil
	case x509.DSA:
		comp := getGenericPublicKeyAlgorithmComponent(x509CertificateWithMetadata.PublicKeyAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.OID = "1.3.14.3.2.12"
		return comp, nil
	case x509.ECDSA:
		comp := getGenericPublicKeyAlgorithmComponent(x509CertificateWithMetadata.PublicKeyAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.OID = "1.2.840.10045.2.1"
		return comp, nil
	case x509.Ed25519:
		comp := getGenericPublicKeyAlgorithmComponent(x509CertificateWithMetadata.PublicKeyAlgorithm, x509CertificateWithMetadata.path)
		comp.CryptoProperties.AlgorithmProperties.Curve = "Ed25519"
		comp.CryptoProperties.OID = "1.3.101.112"
		return comp, nil
	default:
		return getGenericPublicKeyAlgorithmComponent(x509CertificateWithMetadata.PublicKeyAlgorithm, x509CertificateWithMetadata.path), errX509UnknownAlgorithm
	}
}

// Generate a generic CycloneDX component for the public key algorithm
func getGenericPublicKeyAlgorithmComponent(algo x509.PublicKeyAlgorithm, path string) cdx.Component {
	return cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   algo.String(),
		BOMRef: uuid.New().String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
				Primitive:              cdx.CryptoPrimitivePKE,
				ExecutionEnvironment:   cdx.CryptoExecutionEnvironmentUnknown,
				ImplementationPlatform: cdx.ImplementationPlatformUnknown,
				CertificationLevel:     &[]cdx.CryptoCertificationLevel{cdx.CryptoCertificationLevelUnknown},
				CryptoFunctions:        &[]cdx.CryptoFunction{cdx.CryptoFunctionEncapsulate, cdx.CryptoFunctionDecapsulate}, // TODO: Verify if this is true
			},
		},
		Evidence: &cdx.Evidence{
			Occurrences: &[]cdx.EvidenceOccurrence{
				{
					Location: path,
				}},
		},
	}
}
