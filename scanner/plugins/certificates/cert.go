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

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type X509CertificateWithMetadata struct {
	*x509.Certificate
	path   string
	format string
}

var ErrX509UnknownAlgorithm = errors.New("X.509 certificate has unknown algorithm")

func New(cert *x509.Certificate, path string) (*X509CertificateWithMetadata, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}
	return &X509CertificateWithMetadata{
		cert,
		path,
		"X.509",
	}, nil
}

func (x509CertificateWithMetadata *X509CertificateWithMetadata) GenerateCDXComponents() ([]cdx.Component, error) {
	// TODO: Add OIDs
	components := []cdx.Component{x509CertificateWithMetadata.GetCertificateComponent()}
	signatureAlgorithm, err1 := x509CertificateWithMetadata.GetSignatureAlgorithm()
	publicKeyAlgorithm, err2 := x509CertificateWithMetadata.GetPublicKeyAlgorithm()
	publicKey, err3 := x509CertificateWithMetadata.GetPublicKey()

	if err := errors.Join(err1, err2, err3); err != nil {
		return components, err
	}

	return append(components, signatureAlgorithm, publicKeyAlgorithm, publicKey), nil
}

func (x509CertificateWithMetadata *X509CertificateWithMetadata) GetCertificateComponent() cdx.Component {
	return cdx.Component{
		Type: cdx.ComponentTypeCryptographicAsset,
		Name: x509CertificateWithMetadata.Subject.CommonName,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeCertificate,
			CertificateProperties: &cdx.CertificateProperties{
				SubjectName:          x509CertificateWithMetadata.Subject.CommonName,
				IssuerName:           x509CertificateWithMetadata.Issuer.CommonName,
				NotValidBefore:       x509CertificateWithMetadata.NotBefore.Format(time.RFC3339),
				NotValidAfter:        x509CertificateWithMetadata.NotAfter.Format(time.RFC3339),
				CertificateFormat:    x509CertificateWithMetadata.format,
				CertificateExtension: filepath.Ext(x509CertificateWithMetadata.path),
				// TODO: Add AlgorithmRef and Public Key Ref
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

func (x509CertificateWithMetadata *X509CertificateWithMetadata) GetSignatureAlgorithm() (cdx.Component, error) {
	switch x509CertificateWithMetadata.SignatureAlgorithm {
	case x509.MD2WithRSA:
		comp := getGenericSignatureAlgorithm(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		return comp, nil
	case x509.MD5WithRSA:
		comp := getGenericSignatureAlgorithm(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		return comp, nil
	case x509.SHA1WithRSA:
		comp := getGenericSignatureAlgorithm(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "160"
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		return comp, nil
	case x509.SHA256WithRSA:
		comp := getGenericSignatureAlgorithm(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		return comp, nil
	case x509.SHA384WithRSA:
		comp := getGenericSignatureAlgorithm(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "384"
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		return comp, nil
	case x509.SHA512WithRSA:
		comp := getGenericSignatureAlgorithm(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "512"
		comp.CryptoProperties.AlgorithmProperties.Padding = cdx.CryptoPaddingPKCS1v15
		return comp, nil
	case x509.DSAWithSHA1:
		comp := getGenericSignatureAlgorithm(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "160"
		// TODO Padding?
		return comp, nil
	case x509.DSAWithSHA256:
		comp := getGenericSignatureAlgorithm(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"
		// TODO Padding?
		return comp, nil
	case x509.ECDSAWithSHA1:
		comp := getGenericSignatureAlgorithm(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "160"
		// TODO Padding?
		return comp, nil
	case x509.ECDSAWithSHA256:
		comp := getGenericSignatureAlgorithm(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"
		// TODO Padding?
		return comp, nil
	case x509.ECDSAWithSHA384:
		comp := getGenericSignatureAlgorithm(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "384"
		// TODO Padding?
		return comp, nil
	case x509.ECDSAWithSHA512:
		comp := getGenericSignatureAlgorithm(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "512"
		// TODO Padding?
		return comp, nil
	case x509.SHA256WithRSAPSS:
		comp := getGenericSignatureAlgorithm(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "256"
		// TODO Padding?
		return comp, nil
	case x509.SHA384WithRSAPSS:
		comp := getGenericSignatureAlgorithm(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "384"
		// TODO Padding?
		return comp, nil
	case x509.SHA512WithRSAPSS:
		comp := getGenericSignatureAlgorithm(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier = "512"
		// TODO Padding?
		return comp, nil
	case x509.PureEd25519:
		comp := getGenericSignatureAlgorithm(x509CertificateWithMetadata.SignatureAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.Curve = "Ed25519"
		return comp, nil
	default:
		return cdx.Component{}, ErrX509UnknownAlgorithm
	}
}

func getGenericSignatureAlgorithm(algo x509.SignatureAlgorithm) cdx.Component {
	return cdx.Component{
		Type: cdx.ComponentTypeCryptographicAsset,
		Name: algo.String(),
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
				Primitive:              cdx.CryptoPrimitiveSignature,
				ExecutionEnvironment:   cdx.CryptoExecutionEnvironmentUnknown,
				ImplementationPlatform: cdx.ImplementationPlatformUnknown,
				CertificationLevel:     &[]cdx.CryptoCertificationLevel{cdx.CryptoCertificationLevelUnknown},
				CryptoFunctions:        &[]cdx.CryptoFunction{cdx.CryptoFunctionSign, cdx.CryptoFunctionDigest},
			},
		},
	}
}

func (x509CertificateWithMetadata *X509CertificateWithMetadata) GetPublicKey() (cdx.Component, error) {
	switch x509CertificateWithMetadata.PublicKey.(type) {
	case *rsa.PublicKey: // TODO: Set names for all
		comp := getGenericPublicKey()
		pk := x509CertificateWithMetadata.PublicKey.(*rsa.PublicKey)
		size := pk.Size() * 8
		comp.Name = fmt.Sprintf("RSA-%v", size)
		comp.CryptoProperties.RelatedCryptoMaterialProperties.Size = &size
		return comp, nil
	case *dsa.PublicKey:
		comp := getGenericPublicKey()
		pk := x509CertificateWithMetadata.PublicKey.(*dsa.PublicKey)
		comp.Name = "DSA"
		size := pk.Y.BitLen()
		comp.CryptoProperties.RelatedCryptoMaterialProperties.Size = &size
		return comp, nil
	case *ecdsa.PublicKey:
		comp := getGenericPublicKey()
		pk := x509CertificateWithMetadata.PublicKey.(*ecdsa.PublicKey)
		comp.Name = "ECDSA"
		size := pk.Params().BitSize // TODO: Correct?
		comp.CryptoProperties.RelatedCryptoMaterialProperties.Size = &size
		return comp, nil
	case *ed25519.PublicKey:
		comp := getGenericPublicKey()
		pk := x509CertificateWithMetadata.PublicKey.(*ed25519.PublicKey)
		comp.Name = "ED25519"
		size := len(*pk) * 8 // TODO: Correct?
		comp.CryptoProperties.RelatedCryptoMaterialProperties.Size = &size
		return comp, nil
	default:
		return cdx.Component{}, ErrX509UnknownAlgorithm
	}
}

func getGenericPublicKey() cdx.Component {
	return cdx.Component{
		Type: cdx.ComponentTypeCryptographicAsset,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
			RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
				Type: cdx.RelatedCryptoMaterialTypePublicKey,
			},
		},
	}
}

func (x509CertificateWithMetadata *X509CertificateWithMetadata) GetPublicKeyAlgorithm() (cdx.Component, error) { // TODO: Add more details to components
	switch x509CertificateWithMetadata.PublicKeyAlgorithm {
	case x509.RSA:
		comp := getGenericPublicKeyAlgorithm(x509CertificateWithMetadata.PublicKeyAlgorithm)
		return comp, nil
	case x509.DSA:
		comp := getGenericPublicKeyAlgorithm(x509CertificateWithMetadata.PublicKeyAlgorithm)
		return comp, nil
	case x509.ECDSA:
		comp := getGenericPublicKeyAlgorithm(x509CertificateWithMetadata.PublicKeyAlgorithm)
		return comp, nil
	case x509.Ed25519:
		comp := getGenericPublicKeyAlgorithm(x509CertificateWithMetadata.PublicKeyAlgorithm)
		comp.CryptoProperties.AlgorithmProperties.Curve = "Ed25519"
		return comp, nil
	default:
		return cdx.Component{}, ErrX509UnknownAlgorithm
	}
}

func getGenericPublicKeyAlgorithm(algo x509.PublicKeyAlgorithm) cdx.Component {
	return cdx.Component{
		Type: cdx.ComponentTypeCryptographicAsset,
		Name: algo.String(),
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
