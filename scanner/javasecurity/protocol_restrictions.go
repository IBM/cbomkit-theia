package javasecurity

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Represents a single restriction on algorithms by the java.security file
type JavaSecurityAlgorithmRestriction struct {
	name            string
	keySizeOperator keySizeOperator
	keySize         int
}

// keySizeOperator holds operators for the possible comparison functions (e.g. greater than etc.)
type keySizeOperator int

const (
	keySizeOperatorGreaterEqual    keySizeOperator = iota + 1
	keySizeOperatorGreater
	keySizeOperatorLowerEqual
	keySizeOperatorLower
	keySizeOperatorEqual
	keySizeOperatorNotEqual
	keySizeOperatorNone
)

// High-Level function to update a protocol component based on the restriction in the JavaSecurity object
// Returns nil if the updateComponent is not allowed
func (javaSecurity *JavaSecurity) updateProtocolComponent(component cdx.Component) (updatedComponent *cdx.Component, err error) {
	if component.CryptoProperties.AssetType != cdx.CryptoAssetTypeProtocol {
		return &component, fmt.Errorf("scanner: component of type %v cannot be used in function updateProtocolComponent", component.CryptoProperties.AssetType)
	}

	switch component.CryptoProperties.ProtocolProperties.Type {
	case cdx.CryptoProtocolTypeTLS:
		for _, cipherSuites := range *component.CryptoProperties.ProtocolProperties.CipherSuites {
			for _, algorithmRef := range *cipherSuites.Algorithms {
				algo, ok := javaSecurity.bomRefMap[algorithmRef]
				if ok {
					for _, rule := range javaSecurity.tlsDisablesAlgorithms {
						ok, err = rule.eval(*algo)
						if err != nil {
							return updatedComponent, err
						}

						if !ok {
							log.Default().Printf("Component %v is not valid due to algorithm %v", component.Name, algo.Name)
							return nil, nil
						}
					}
				}
			}
		}
	default:
		return &component, nil
	}

	return &component, nil
}

// TODO: Make a method to check for protocol restrictions too (e.g. TLS and not only algos like RSA)

// Evaluates if a single component is allowed based on a single restriction
func (javaSecurityAlgorithmRestriction JavaSecurityAlgorithmRestriction) eval(component cdx.Component) (allowed bool, err error) {
	allowed = true

	if component.CryptoProperties.AssetType != cdx.CryptoAssetTypeAlgorithm {
		return allowed, fmt.Errorf("scanner: cannot evaluate components other than algorithm for applying restrictions")
	}

	subAlgorithms := strings.Split(javaSecurityAlgorithmRestriction.name, "with")

	for _, subAlgorithm := range subAlgorithms {
		if subAlgorithm == component.Name {
			if component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier == "" {
				return allowed, err
			}
			param, err := strconv.Atoi(component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier)
			if err != nil {
				return allowed, err
			}
			switch javaSecurityAlgorithmRestriction.keySizeOperator {
			case keySizeOperatorLowerEqual:
				allowed = !(param <= javaSecurityAlgorithmRestriction.keySize)
			case keySizeOperatorLower:
				allowed = !(param < javaSecurityAlgorithmRestriction.keySize)
			case keySizeOperatorEqual:
				allowed = !(param == javaSecurityAlgorithmRestriction.keySize)
			case keySizeOperatorNotEqual:
				allowed = !(param != javaSecurityAlgorithmRestriction.keySize)
			case keySizeOperatorGreaterEqual:
				allowed = !(param >= javaSecurityAlgorithmRestriction.keySize)
			case keySizeOperatorGreater:
				allowed = !(param > javaSecurityAlgorithmRestriction.keySize)
			case keySizeOperatorNone:
				allowed = false
			default:
				return allowed, fmt.Errorf("scanner: invalid keySizeOperator in JavaSecurityAlgorithmRestriction: %v", javaSecurityAlgorithmRestriction.keySizeOperator)
			}
		}

		if !allowed {
			return allowed, err
		}
	}

	return allowed, err
}
