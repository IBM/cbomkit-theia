package pemutility

import (
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
)

type Filter struct {
	FilterType PEMTypeFilterType
	List       []PEMBlockType
}

type PEMTypeFilterType bool

const (
	PEMTypeFilterTypeAllowlist PEMTypeFilterType = true
	PEMTypeFilterTypeBlocklist PEMTypeFilterType = false
)

type PEMBlockType string

const (
	PEMBlockTypeCertificate         PEMBlockType = "CERTIFICATE"
	PEMBlockTypePrivateKey          PEMBlockType = "PRIVATE KEY"
	PEMBlockTypeEncryptedPrivateKey PEMBlockType = "ENCRYPTED PRIVATE KEY"
	PEMBlockTypePublicKey           PEMBlockType = "PUBLIC KEY"
	PEMBlockTypeECPrivateKey        PEMBlockType = "EC PRIVATE KEY"
	PEMBlockTypeRSAPrivateKey       PEMBlockType = "RSA PRIVATE KEY"
	PEMBlockTypeRSAPublicKey        PEMBlockType = "RSA PUBLIC KEY"
	PEMBlockTypeOther               PEMBlockType = "other"
)

func parsePEMToBlocks(raw []byte) []*pem.Block {
	rest := raw
	var blocks []*pem.Block
	for len(rest) != 0 {
		var newBlock *pem.Block
		newBlock, rest = pem.Decode(rest)
		if newBlock != nil {
			blocks = append(blocks, newBlock)
		} else {
			break
		}
	}
	return blocks
}

func ParsePEMToBlocksWithTypes(raw []byte) map[*pem.Block]PEMBlockType {
	blocks := parsePEMToBlocks(raw)

	blocksWithType := make(map[*pem.Block]PEMBlockType, len(blocks))

	for _, block := range blocks {
		blocksWithType[block] = PEMBlockType(block.Type)
	}

	return blocksWithType
}

func ParsePEMToBlocksWithTypeFilter(raw []byte, filter Filter) map[*pem.Block]PEMBlockType {
	blocksWithType := ParsePEMToBlocksWithTypes(raw)
	filteredBlocksWithType := make(map[*pem.Block]PEMBlockType)

	for block, t := range blocksWithType {
		if slices.Contains(filter.List, t) == bool(filter.FilterType) {
			filteredBlocksWithType[block] = t
		}
	}

	return filteredBlocksWithType
}

type ComponentBuilder struct {
	C cdx.Component
}

var errUnknownKeyAlgorithm = errors.New("key block uses unknown algorithm")

func GenerateComponentsFromKeyBlock(block *pem.Block, occurrences ...cdx.EvidenceOccurrence) ([]cdx.Component, error) {
	cb := NewComponentBuilder()
	cb.SetOccurrences(occurrences...)

	switch PEMBlockType(block.Type) {

	case PEMBlockTypePrivateKey:
		cb.SetPrivateKeyComponent()

		genericKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return []cdx.Component{}, err
		}

		switch key := genericKey.(type) {
		case *rsa.PrivateKey:
			cb.SetRSAPrivateKeyComponent()
			privateKeyComponent := cb.GetComponent()
			cb.SetRSAPublicKeyComponent(&key.PublicKey)
			return []cdx.Component{privateKeyComponent, cb.GetComponent()}, nil
		case *ecdsa.PrivateKey:
			cb.SetECDSAPrivateKeyComponent(key)
			privateKeyComponent := cb.GetComponent()
			cb.SetECDSAPublicKeyComponent(&key.PublicKey)
			return []cdx.Component{privateKeyComponent, cb.GetComponent()}, nil
		case ed25519.PrivateKey:
			cb.SetED25519PrivateKeyComponent()
			privateKeyComponent := cb.GetComponent()
			cb.SetED25519PublicKeyComponent(key.Public().(ed25519.PublicKey)) // TODO: This cast might be unsafe
			return []cdx.Component{privateKeyComponent, cb.GetComponent()}, nil
		case *ecdh.PrivateKey:
			cb.SetECDHPrivateKeyComponent()
			privateKeyComponent := cb.GetComponent()
			cb.SetECDHPublicKeyComponent(key.Public().(*ecdh.PublicKey))
			return []cdx.Component{privateKeyComponent, cb.GetComponent()}, nil
		default:
			return []cdx.Component{}, errUnknownKeyAlgorithm
		}

	case PEMBlockTypeECPrivateKey:
		cb.SetPrivateKeyComponent()

		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return []cdx.Component{}, err
		}
		cb.SetECDSAPrivateKeyComponent(key)
		privateKeyComponent := cb.GetComponent()
		cb.SetECDSAPublicKeyComponent(&key.PublicKey)
		return []cdx.Component{privateKeyComponent, cb.GetComponent()}, nil

	case PEMBlockTypeRSAPrivateKey:
		cb.SetPrivateKeyComponent()

		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return []cdx.Component{}, err
		}
		cb.SetRSAPrivateKeyComponent()
		privateKeyComponent := cb.GetComponent()
		cb.SetRSAPublicKeyComponent(&key.PublicKey)
		return []cdx.Component{privateKeyComponent, cb.GetComponent()}, nil

	case PEMBlockTypePublicKey:
		cb.SetPublicKeyComponent()
		cb.SetValue(block.Bytes)

		genericKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return []cdx.Component{}, err
		}

		switch key := genericKey.(type) {
		case *rsa.PublicKey:
			cb.SetRSAPublicKeyComponent(key)
			return []cdx.Component{cb.GetComponent()}, nil
		case *dsa.PublicKey:
			cb.SetDSAPublicKeyComponent(key)
			return []cdx.Component{cb.GetComponent()}, nil
		case *ecdsa.PublicKey:
			cb.SetECDSAPublicKeyComponent(key)
			return []cdx.Component{cb.GetComponent()}, nil
		case *ed25519.PublicKey:
			cb.SetED25519PublicKeyComponent(*key)
			return []cdx.Component{cb.GetComponent()}, nil
		case *ecdh.PublicKey:
			cb.SetECDHPublicKeyComponent(key)
			return []cdx.Component{cb.GetComponent()}, nil
		default:
			return []cdx.Component{}, errUnknownKeyAlgorithm
		}

	case PEMBlockTypeRSAPublicKey:
		cb.SetPublicKeyComponent()
		cb.SetValue(block.Bytes)

		key, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return []cdx.Component{}, err
		}
		cb.SetRSAPublicKeyComponent(key)
		return []cdx.Component{cb.GetComponent()}, nil

	default:
		return []cdx.Component{}, fmt.Errorf("could not generate cyclone-dx component from pem: pem file block type is unknown or not a key")
	}
}

func NewComponentBuilder() *ComponentBuilder {
	return &ComponentBuilder{
		C: cdx.Component{
			BOMRef: uuid.New().String(),
		},
	}
}

func NewComponentBuilderFromComponent(c cdx.Component) *ComponentBuilder {
	return &ComponentBuilder{
		C: c,
	}
}

func (cb *ComponentBuilder) GetComponent() cdx.Component {
	return *cb.C // We need to somehow account for the problem that we need two components
}

func (cb *ComponentBuilder) SetOccurrences(occurrences ...cdx.EvidenceOccurrence) {
	cb.C.Evidence = &cdx.Evidence{
		Occurrences: &occurrences,
	}
}

func (cb *ComponentBuilder) SetValue(value []byte) {
	cb.C.CryptoProperties.RelatedCryptoMaterialProperties.Value = base64.StdEncoding.EncodeToString(value)
}

func (cb *ComponentBuilder) SetPublicKeyComponent() {
	cb.C.Type = cdx.ComponentTypeCryptographicAsset
	cb.C.CryptoProperties = &cdx.CryptoProperties{
		AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
		RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
			Type:   cdx.RelatedCryptoMaterialTypePublicKey,
			Format: "PEM",
		},
	}
}

func (cb *ComponentBuilder) SetPrivateKeyComponent() {
	cb.C.Type = cdx.ComponentTypeCryptographicAsset
	cb.C.CryptoProperties = &cdx.CryptoProperties{
		AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
		RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{
			Type:   cdx.RelatedCryptoMaterialTypePrivateKey,
			Format: "PEM",
		},
	}
}

func (cb *ComponentBuilder) SetRSAPublicKeyComponent(key *rsa.PublicKey) {
	size := key.Size() * 8
	cb.C.Name = fmt.Sprintf("RSA-%v", size)
	cb.C.CryptoProperties.RelatedCryptoMaterialProperties.Size = &size
	cb.C.CryptoProperties.OID = "1.2.840.113549.1.1.1"
}

func (cb *ComponentBuilder) SetRSAPrivateKeyComponent() {
	cb.C.Name = "RSA"
	cb.C.CryptoProperties.OID = "1.2.840.113549.1.1.1"
}

func (cb *ComponentBuilder) SetECDSAPublicKeyComponent(key *ecdsa.PublicKey) {
	cb.C.Name = "ECDSA"
	cb.C.Description = fmt.Sprintf("Curve: %v", key.Curve.Params().Name)
	cb.C.CryptoProperties.OID = "1.2.840.10045.2.1"
}

func (cb *ComponentBuilder) SetECDSAPrivateKeyComponent(key *ecdsa.PrivateKey) {
	cb.C.Name = "ECDSA"
	cb.C.Description = fmt.Sprintf("Curve: %v", key.Curve.Params().Name)
}

func (cb *ComponentBuilder) SetED25519PublicKeyComponent(key ed25519.PublicKey) {
	cb.C.Name = "ED25519"
	size := len([]byte(key)) * 8
	cb.C.CryptoProperties.RelatedCryptoMaterialProperties.Size = &size
}

func (cb *ComponentBuilder) SetED25519PrivateKeyComponent() {
	cb.C.Name = "ED25519"
}

func (cb *ComponentBuilder) SetECDHPublicKeyComponent(key *ecdh.PublicKey) {
	cb.C.Name = "ECDH"
	size := len(key.Bytes()) * 8
	cb.C.CryptoProperties.RelatedCryptoMaterialProperties.Size = &size
	cb.C.CryptoProperties.OID = "1.2.840.10045.2.1"
}

func (cb *ComponentBuilder) SetECDHPrivateKeyComponent() {
	cb.C.Name = "ECDH"
}

func (cb *ComponentBuilder) SetDSAPublicKeyComponent(key *dsa.PublicKey) {
	cb.C.Name = "DSA"
	size := key.Y.BitLen()
	cb.C.CryptoProperties.RelatedCryptoMaterialProperties.Size = &size
	cb.C.CryptoProperties.OID = "1.3.14.3.2.12"
}
