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


// Evaluates if a single component is allowed based on a single restriction
// Follows the JDK implementation https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/sun/security/util/DisabledAlgorithmConstraints.java
func (javaSecurityAlgorithmRestriction JavaSecurityAlgorithmRestriction) eval(component cdx.Component) (allowed bool, err error) {
	allowed = true
	if component.CryptoProperties.AssetType != cdx.CryptoAssetTypeAlgorithm &&
	component.CryptoProperties.AssetType != cdx.CryptoAssetTypeProtocol {
		return allowed, fmt.Errorf("scanner: cannot evaluate components other than algorithm for applying restrictions")
	}

	subRestrictions := strings.Split(javaSecurityAlgorithmRestriction.name, "with")

	for _, subRestriction := range subRestrictions {
		if strings.EqualFold(subRestriction, component.Name) {
			if component.CryptoProperties.AssetType == cdx.CryptoAssetTypeProtocol {
				// The component is a protocol and we do not have any parameters to compare

				return false, err 
			} 

			if component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier == "" {
				return true, err
			}
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
