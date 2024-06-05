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
	keySizeOperatorGreaterEqual keySizeOperator = iota + 1
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
			// Test the protocol itself
			protocolAllowed, err := evalAll(&javaSecurity.tlsDisablesAlgorithms, component)

			if err != nil {
				return updatedComponent, err
			}

			if !protocolAllowed {
				log.Default().Printf("Component %v is not valid", component.Name)
				return nil, nil
			}

			// Test all algorithms in the protocol
			for _, algorithmRef := range *cipherSuites.Algorithms {
				algo, ok := javaSecurity.bomRefMap[algorithmRef]
				if ok {
					algoAllowed, err := evalAll(&javaSecurity.tlsDisablesAlgorithms, *algo)
					if err != nil {
						return updatedComponent, err
					}

					if !algoAllowed {
						log.Default().Printf("Component %v is not valid due to algorithm %v", component.Name, algo.Name)
						return nil, nil
					}
				}
			}
		}
	default:
		return &component, nil
	}

	return &component, nil
}

func evalAll(javaSecurityAlgorithmRestrictions *[]JavaSecurityAlgorithmRestriction, component cdx.Component) (allowed bool, err error) {
	for _, javaSecurityAlgorithmRestriction := range *javaSecurityAlgorithmRestrictions {
		allowed, err := javaSecurityAlgorithmRestriction.eval(component)
		if !allowed || err != nil {
			return allowed, err
		}
	}
	return true, nil
}

// TODO: Also account for algorithm components that are only there due to this protocol and should therefore be removed if the protocol was removed too (or should they?)

// Evaluates if a single component is allowed based on a single restriction
// Follows the JDK implementation https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/sun/security/util/DisabledAlgorithmConstraints.java
func (javaSecurityAlgorithmRestriction JavaSecurityAlgorithmRestriction) eval(component cdx.Component) (allowed bool, err error) {
	allowed = true
	if component.CryptoProperties.AssetType != cdx.CryptoAssetTypeAlgorithm &&
		component.CryptoProperties.AssetType != cdx.CryptoAssetTypeProtocol {
		return allowed, fmt.Errorf("scanner: cannot evaluate components other than algorithm for applying restrictions")
	}

	// Format could be: <digest>with<encryption>and<mgf>
	replacer := strings.NewReplacer("with", " ", "and", " ")
	subAlgorithms := strings.Fields(replacer.Replace(component.Name))

	// We also need to test the full name
	if len(subAlgorithms) > 1 {
		subAlgorithms = append(subAlgorithms, component.Name)
	}

	for _, subAlgorithm := range subAlgorithms {
		// TODO: Maybe do less "perfect" string matching? (e.g. "-" --> "_") Or even a different approach than string matching?
		if strings.EqualFold(javaSecurityAlgorithmRestriction.name, subAlgorithm) {
			if component.CryptoProperties.AssetType == cdx.CryptoAssetTypeProtocol {
				// The component is a protocol and we do not have any parameters to compare
				return false, err
			}

			// There is no need to test further if the component does not provide a keySize
			if component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier == "" {
				if javaSecurityAlgorithmRestriction.keySizeOperator != keySizeOperatorNone {
					log.Default().Printf("stopped evaluation of %v due to insufficient information", subAlgorithm)
					return true, err // We actually need a keySize so we cannot go on here
				} else {
					return false, err // Names match and we do not need a keySize --> The algorithm is not allowed!
				}
			}

			// Parsing the key size
			param, err := strconv.Atoi(component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier)
			if err != nil {
				return true, err
			}

			if param <= 0 || param > 2147483647 {
				return false, err // Following Java reference implementation (see https://github.com/openjdk/jdk/blob/4f1a10f84bcfadef263a0890b6834ccd3d5bb52f/src/java.base/share/classes/sun/security/util/DisabledAlgorithmConstraints.java#L944 and https://github.com/openjdk/jdk/blob/4f1a10f84bcfadef263a0890b6834ccd3d5bb52f/src/java.base/share/classes/sun/security/util/DisabledAlgorithmConstraints.java#L843)
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
				return true, fmt.Errorf("scanner: invalid keySizeOperator in JavaSecurityAlgorithmRestriction: %v", javaSecurityAlgorithmRestriction.keySizeOperator)
			}
		}

		if !allowed {
			return allowed, err
		}
	}

	return true, err
}
