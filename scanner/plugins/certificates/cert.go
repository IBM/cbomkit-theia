package certificates

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
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

// Generate CycloneDX components from the x509CertificateWithMetadata (e.g. certificate, signature algorithm, public key and public key algorithm)
func (x509CertificateWithMetadata *x509CertificateWithMetadata) generateCDXComponents() ([]cdx.Component, error) {
	dag := bomdag.NewBomDAG()

	// Creating BOM Components
	certificate := x509CertificateWithMetadata.getCertificateComponent()
	signatureAlgorithm, err1 := x509CertificateWithMetadata.getSignatureAlgorithmComponent()
	publicKeyAlgorithm, err2 := x509CertificateWithMetadata.getPublicKeyAlgorithmComponent()
	publicKey, err3 := x509CertificateWithMetadata.getPublicKeyComponent()

	err := errors.Join(err1, err2, err3)
	if err != nil {
		return []cdx.Component{}, err
	}

	// Adding BOM Components to DAG
	certificateHash, err1 := dag.GetVertexOrAddNew(certificate)
	publicKeyAlgorithmHash, err2 := dag.GetVertexOrAddNew(publicKeyAlgorithm)
	publicKeyHash, err3 := dag.GetVertexOrAddNew(publicKey)

	var signatureAlgorithmHash, signatureAlgorithmPKEHash, signatureAlgorithmHashHash [32]byte
	var err4, err5, err6 error
	if signatureAlgorithm.signature != nil {
		signatureAlgorithmHash, err4 = dag.GetVertexOrAddNew(*signatureAlgorithm.signature)
	}
	if signatureAlgorithm.pke != nil {
		signatureAlgorithmPKEHash, err5 = dag.GetVertexOrAddNew(*signatureAlgorithm.pke)
	}
	if signatureAlgorithm.hash != nil {
		signatureAlgorithmHashHash, err6 = dag.GetVertexOrAddNew(*signatureAlgorithm.hash)
	}

	err = errors.Join(err1, err2, err3, err4, err5, err6)
	if err != nil {
		return []cdx.Component{}, err
	}

	// Creating Edges in DAG
	err6 = dag.AddEdge(dag.Root, certificateHash)
	err1 = dag.AddEdge(certificateHash, publicKeyHash,
		bomdag.EdgeDependencyType(bomdag.BomDAGDependencyTypeCertificatePropertiesSubjectPublicKeyRef),
		bomdag.EdgeDependencyType(bomdag.BomDAGDependencyTypeDependsOn))
	err2 = dag.AddEdge(publicKeyHash, publicKeyAlgorithmHash,
		bomdag.EdgeDependencyType(bomdag.BomDAGDependencyTypeRelatedCryptoMaterialPropertiesAlgorithmRef),
		bomdag.EdgeDependencyType(bomdag.BomDAGDependencyTypeDependsOn))
	err3 = dag.AddEdge(certificateHash, signatureAlgorithmHash,
		bomdag.EdgeDependencyType(bomdag.BomDAGDependencyTypeCertificatePropertiesSignatureAlgorithmRef),
		bomdag.EdgeDependencyType(bomdag.BomDAGDependencyTypeDependsOn))
	err4 = dag.AddEdge(signatureAlgorithmHash, signatureAlgorithmPKEHash,
		bomdag.EdgeDependencyType(bomdag.BomDAGDependencyTypeDependsOn))
	err5 = dag.AddEdge(signatureAlgorithmHash, signatureAlgorithmHashHash,
		bomdag.EdgeDependencyType(bomdag.BomDAGDependencyTypeDependsOn))

	err = errors.Join(err1, err2, err3, err4, err5, err6)
	if err != nil {
		return []cdx.Component{}, err
	}

	components, dependencies, err := dag.GetCDXComponents()

	if err != nil {
		return []cdx.Component{}, err
	}

	print(dependencies) // TODO

	return components, nil
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
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		comp.CryptoProperties.OID = "1.3.14.7.2.3.1"

		hash := getGenericHashAlgorithmComponent()
		hash.Name = "MD2"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "2"
		hash.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingOther

		pke := getGenericPKEAlgorithmComponent()
		pke.Name = "RSA"

		// TODO: Link the components

		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.MD5WithRSA:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		comp.CryptoProperties.OID = "1.3.14.3.2.3"

		hash := getGenericHashAlgorithmComponent()
		hash.Name = "MD5"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "5"

		pke := getGenericPKEAlgorithmComponent()
		pke.Name = "RSA"

		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.SHA1WithRSA:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "160"
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		comp.CryptoProperties.OID = "1.2.840.113549.1.1.5"

		hash := getGenericHashAlgorithmComponent()
		hash.Name = "SHA1"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "1"

		pke := getGenericPKEAlgorithmComponent()
		pke.Name = "RSA"

		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.SHA256WithRSA:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		comp.CryptoProperties.OID = "1.2.840.113549.1.1.11"

		hash := getGenericHashAlgorithmComponent()
		hash.Name = "SHA256"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"

		pke := getGenericPKEAlgorithmComponent()
		pke.Name = "RSA"

		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.SHA384WithRSA:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "384"
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		comp.CryptoProperties.OID = "1.2.840.113549.1.1.12"

		hash := getGenericHashAlgorithmComponent()
		hash.Name = "SHA384"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "384"

		pke := getGenericPKEAlgorithmComponent()
		pke.Name = "RSA"

		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.SHA512WithRSA:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "512"
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		comp.CryptoProperties.OID = "1.2.840.113549.1.1.13"

		hash := getGenericHashAlgorithmComponent()
		hash.Name = "SHA512"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "512"

		pke := getGenericPKEAlgorithmComponent()
		pke.Name = "RSA"

		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.DSAWithSHA1:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "160"
		comp.CryptoProperties.OID = "1.3.14.3.2.27"

		hash := getGenericHashAlgorithmComponent()
		hash.Name = "SHA1"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "1"

		pke := getGenericPKEAlgorithmComponent()
		pke.Name = "DSA"

		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.DSAWithSHA256:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"
		comp.CryptoProperties.OID = "2.16.840.1.101.3.4.3.2"

		hash := getGenericHashAlgorithmComponent()
		hash.Name = "SHA256"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"

		pke := getGenericPKEAlgorithmComponent()
		pke.Name = "DSA"
		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.ECDSAWithSHA1:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "160"
		comp.CryptoProperties.OID = "1.2.840.10045.4.1"

		hash := getGenericHashAlgorithmComponent()
		hash.Name = "SHA1"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "1"

		pke := getGenericPKEAlgorithmComponent()
		pke.Name = "ECDSA"
		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.ECDSAWithSHA256:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"
		comp.CryptoProperties.OID = "1.2.840.10045.4.3.2"

		hash := getGenericHashAlgorithmComponent()
		hash.Name = "SHA256"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"

		pke := getGenericPKEAlgorithmComponent()
		pke.Name = "ECDSA"
		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.ECDSAWithSHA384:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "384"
		comp.CryptoProperties.OID = "1.2.840.10045.4.3.3"

		hash := getGenericHashAlgorithmComponent()
		hash.Name = "SHA384"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "384"

		pke := getGenericPKEAlgorithmComponent()
		pke.Name = "ECDSA"
		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.ECDSAWithSHA512:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "512"
		comp.CryptoProperties.OID = "1.2.840.10045.4.3.4"

		hash := getGenericHashAlgorithmComponent()
		hash.Name = "SHA512"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "512"

		pke := getGenericPKEAlgorithmComponent()
		pke.Name = "ECDSA"
		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.SHA256WithRSAPSS:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"
		comp.CryptoProperties.OID = "1.2.840.113549.1.1.11"

		hash := getGenericHashAlgorithmComponent()
		hash.Name = "SHA256"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"

		pke := getGenericPKEAlgorithmComponent()
		pke.Name = "RSAPSS"
		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.SHA384WithRSAPSS:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "384"
		comp.CryptoProperties.OID = "1.2.840.113549.1.1.12"

		hash := getGenericHashAlgorithmComponent()
		hash.Name = "SHA384"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "384"

		pke := getGenericPKEAlgorithmComponent()
		pke.Name = "RSAPSS"
		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.SHA512WithRSAPSS:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "512"
		comp.CryptoProperties.OID = "1.2.840.113549.1.1.13"

		hash := getGenericHashAlgorithmComponent()
		hash.Name = "SHA512"
		hash.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "512"

		pke := getGenericPKEAlgorithmComponent()
		pke.Name = "RSAPSS"
		return signatureAlgorithmResult{
			signature: &comp,
			hash:      &hash,
			pke:       &pke,
		}, nil
	case x509.PureEd25519:
		comp := getGenericSignatureAlgorithmComponent(x509CertificateWithMetadata.SignatureAlgorithm)
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
func getGenericSignatureAlgorithmComponent(algo x509.SignatureAlgorithm) cdx.Component {
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
	}
}

// Generate a generic CycloneDX component for a hash algorithm
func getGenericHashAlgorithmComponent() cdx.Component {
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
	}
}

// Generate a generic CycloneDX component for a hash algorithm
func getGenericPKEAlgorithmComponent() cdx.Component {
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
	}
}

// Generate the CycloneDX component for the public key
func (x509CertificateWithMetadata *x509CertificateWithMetadata) getPublicKeyComponent() (cdx.Component, error) {
	switch x509CertificateWithMetadata.PublicKey.(type) {
	case *rsa.PublicKey:
		comp := getGenericPublicKeyComponent()
		pk := x509CertificateWithMetadata.PublicKey.(*rsa.PublicKey)
		size := pk.Size() * 8
		comp.Name = fmt.Sprintf("RSA-%v", size)
		comp.CryptoProperties.RelatedCryptoMaterialProperties.Size = &size
		comp.CryptoProperties.OID = "1.2.840.113549.1.1.1"
		return comp, nil
	case *dsa.PublicKey:
		comp := getGenericPublicKeyComponent()
		pk := x509CertificateWithMetadata.PublicKey.(*dsa.PublicKey)
		comp.Name = "DSA"
		size := pk.Y.BitLen()
		comp.CryptoProperties.RelatedCryptoMaterialProperties.Size = &size
		comp.CryptoProperties.OID = "1.3.14.3.2.12"
		return comp, nil
	case *ecdsa.PublicKey:
		comp := getGenericPublicKeyComponent()
		comp.CryptoProperties.OID = "1.2.840.10045.2.1"
		return comp, nil
	case *ed25519.PublicKey:
		comp := getGenericPublicKeyComponent()
		comp.Name = "ED25519"
		comp.CryptoProperties.OID = "1.3.101.112"
		return comp, nil
	default:
		return cdx.Component{}, errX509UnknownAlgorithm
	}
}

// Generate a generic CycloneDX component for the public key
func getGenericPublicKeyComponent() cdx.Component {
	return cdx.Component{
		Type:   cdx.ComponentTypeCryptographicAsset,
		BOMRef: uuid.New().String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type: cdx.RelatedCryptoMaterialTypePublicKey,
			},
		},
	}
}

// Generate the CycloneDX component for the public key algorithm
func (x509CertificateWithMetadata *x509CertificateWithMetadata) getPublicKeyAlgorithmComponent() (cdx.Component, error) {
	switch x509CertificateWithMetadata.PublicKeyAlgorithm {
	case x509.RSA:
		comp := getGenericPublicKeyAlgorithmComponent(x509CertificateWithMetadata.PublicKeyAlgorithm)
		comp.CryptoProperties.OID = "1.2.840.113549.1.1.1"
		return comp, nil
	case x509.DSA:
		comp := getGenericPublicKeyAlgorithmComponent(x509CertificateWithMetadata.PublicKeyAlgorithm)
		comp.CryptoProperties.OID = "1.3.14.3.2.12"
		return comp, nil
	case x509.ECDSA:
		comp := getGenericPublicKeyAlgorithmComponent(x509CertificateWithMetadata.PublicKeyAlgorithm)
		comp.CryptoProperties.OID = "1.2.840.10045.2.1"
		return comp, nil
	case x509.Ed25519:
		comp := getGenericPublicKeyAlgorithmComponent(x509CertificateWithMetadata.PublicKeyAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.Curve = "Ed25519"
		comp.CryptoProperties.OID = "1.3.101.112"
		return comp, nil
	default:
		return getGenericPublicKeyAlgorithmComponent(x509CertificateWithMetadata.PublicKeyAlgorithm), errX509UnknownAlgorithm
	}
}

// Generate a generic CycloneDX component for the public key algorithm
func getGenericPublicKeyAlgorithmComponent(algo x509.PublicKeyAlgorithm) cdx.Component {
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
	}
}
