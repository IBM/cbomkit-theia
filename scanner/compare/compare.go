package compare

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"reflect"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type cleaner struct {
	set   func(comp *cdx.Component, value any)
	unset func(comp *cdx.Component) any
}

func HashCDXComponentWithoutRefs(a cdx.Component) [32]byte {
	cleaners := []cleaner{
		{
			set: func(comp *cdx.Component, value any) {
				comp.BOMRef = value.(string)
			},
			unset: func(comp *cdx.Component) any {
				temp := comp.BOMRef
				comp.BOMRef = ""
				return temp
			},
		},
		{
			set: func(comp *cdx.Component, value any) {
				if comp.CryptoProperties != nil && comp.CryptoProperties.CertificateProperties != nil {
					comp.CryptoProperties.CertificateProperties.SignatureAlgorithmRef = value.(cdx.BOMReference)
				}
			},
			unset: func(comp *cdx.Component) any {
				if comp.CryptoProperties != nil && comp.CryptoProperties.CertificateProperties != nil {
					temp := comp.CryptoProperties.CertificateProperties.SignatureAlgorithmRef
					comp.CryptoProperties.CertificateProperties.SignatureAlgorithmRef = ""
					return temp
				}
				return nil
			},
		},
		{
			set: func(comp *cdx.Component, value any) {
				if comp.CryptoProperties != nil && comp.CryptoProperties.CertificateProperties != nil {
					comp.CryptoProperties.CertificateProperties.SubjectPublicKeyRef = value.(cdx.BOMReference)
				}
			},
			unset: func(comp *cdx.Component) any {
				if comp.CryptoProperties != nil && comp.CryptoProperties.CertificateProperties != nil {
					temp := comp.CryptoProperties.CertificateProperties.SubjectPublicKeyRef
					comp.CryptoProperties.CertificateProperties.SubjectPublicKeyRef = ""
					return temp
				}
				return nil
			},
		},
		{
			set: func(comp *cdx.Component, value any) {
				if comp.CryptoProperties != nil && comp.CryptoProperties.RelatedCryptoMaterialProperties != nil {
					comp.CryptoProperties.RelatedCryptoMaterialProperties.AlgorithmRef = value.(cdx.BOMReference)
				}
			},
			unset: func(comp *cdx.Component) any {
				if comp.CryptoProperties != nil && comp.CryptoProperties.RelatedCryptoMaterialProperties != nil {
					temp := comp.CryptoProperties.RelatedCryptoMaterialProperties.AlgorithmRef
					comp.CryptoProperties.RelatedCryptoMaterialProperties.AlgorithmRef = ""
					return temp
				}
				return nil
			},
		},
		{
			set: func(comp *cdx.Component, value any) {
				if comp.CryptoProperties != nil && comp.CryptoProperties.RelatedCryptoMaterialProperties != nil && comp.CryptoProperties.RelatedCryptoMaterialProperties.SecuredBy != nil {
					comp.CryptoProperties.RelatedCryptoMaterialProperties.SecuredBy.AlgorithmRef = value.(cdx.BOMReference)
				}
			},
			unset: func(comp *cdx.Component) any {
				if comp.CryptoProperties != nil && comp.CryptoProperties.RelatedCryptoMaterialProperties != nil && comp.CryptoProperties.RelatedCryptoMaterialProperties.SecuredBy != nil {
					temp := comp.CryptoProperties.RelatedCryptoMaterialProperties.SecuredBy.AlgorithmRef
					comp.CryptoProperties.RelatedCryptoMaterialProperties.SecuredBy.AlgorithmRef = ""
					return temp
				}
				return nil
			},
		},
		{
			set: func(comp *cdx.Component, value any) {
				if comp.CryptoProperties != nil && comp.CryptoProperties.ProtocolProperties != nil && comp.CryptoProperties.ProtocolProperties.CryptoRefArray != nil {
					comp.CryptoProperties.ProtocolProperties.CryptoRefArray = value.(*[]cdx.BOMReference)
				}
			},
			unset: func(comp *cdx.Component) any {
				if comp.CryptoProperties != nil && comp.CryptoProperties.ProtocolProperties != nil && comp.CryptoProperties.ProtocolProperties.CryptoRefArray != nil {
					temp := comp.CryptoProperties.ProtocolProperties.CryptoRefArray
					comp.CryptoProperties.ProtocolProperties.CryptoRefArray = new([]cdx.BOMReference)
					return temp
				}
				return nil
			},
		},
	}

	temp := make([]any, len(cleaners))

	for i, cleaner := range cleaners {
		temp[i] = cleaner.unset(&a)
	}

	defer func(cleaners []cleaner, a cdx.Component, temp []any) {
		for i, cleaner := range cleaners {
			temp[i] = cleaner.unset(&a)
		}
	}(cleaners, a, temp)

	var b bytes.Buffer
	gob.NewEncoder(&b).Encode(a)
	return sha256.Sum256(b.Bytes())
}

func CompareCDXComponentWithoutRefs(a cdx.Component, b cdx.Component) int {
	aHash := HashCDXComponentWithoutRefs(a)
	bHash := HashCDXComponentWithoutRefs(b)
	return strings.Compare(hex.EncodeToString(aHash[:]), hex.EncodeToString(bHash[:]))
}

func CompareComponentSliceWithoutRefs(a []cdx.Component, b []cdx.Component) int {
	slices.SortFunc(a, CompareCDXComponentWithoutRefs)
	slices.SortFunc(b, CompareCDXComponentWithoutRefs)
	return slices.CompareFunc(a, b, CompareCDXComponentWithoutRefs)
}

// This should only be used in testing
func EqualBOMWithoutRefs(a cdx.BOM, b cdx.BOM) bool {
	if a.SerialNumber != b.SerialNumber {
		return false
	}
	if a.Version != b.Version {
		return false
	}
	if !reflect.DeepEqual(a.Metadata, b.Metadata) {
		return false
	}
	if a.Components != nil && b.Components != nil {
		if CompareComponentSliceWithoutRefs(*a.Components, *b.Components) != 0 {
			return false
		}
	} else if !(a.Components == nil && b.Components == nil) {
		return false
	}

	if !reflect.DeepEqual(a.Services, b.Services) {
		return false
	}
	if !reflect.DeepEqual(a.ExternalReferences, b.ExternalReferences) {
		return false
	}

	// This comparison of the dependency slices could be better. It is currently pretty minimal
	if a.Dependencies != nil && b.Dependencies != nil {
		if len(*a.Dependencies) != len(*b.Dependencies) {
			return false
		}
	} else if !(a.Dependencies == nil && b.Dependencies == nil) {
		return false
	}

	if !reflect.DeepEqual(a.Compositions, b.Compositions) {
		return false
	}

	if !reflect.DeepEqual(a.Properties, b.Properties) {
		return false
	}

	if !reflect.DeepEqual(a.Vulnerabilities, b.Vulnerabilities) {
		return false
	}

	if !reflect.DeepEqual(a.Annotations, b.Annotations) {
		return false
	}

	if !reflect.DeepEqual(a.Formulation, b.Formulation) {
		return false
	}

	if !reflect.DeepEqual(a.Declarations, b.Declarations) {
		return false
	}

	if !reflect.DeepEqual(a.Definitions, b.Definitions) {
		return false
	}

	return true
}
