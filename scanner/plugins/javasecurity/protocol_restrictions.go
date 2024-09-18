// Copyright 2024 IBM
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package javasecurity

import (
	go_errors "errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	advancedcomponentslice "github.com/IBM/cbomkit-theia/scanner/componentwithconfidenceslice"
	"github.com/IBM/cbomkit-theia/scanner/confidencelevel"
	scanner_errors "github.com/IBM/cbomkit-theia/scanner/errors"

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
func (javaSecurity *JavaSecurity) updateProtocolComponent(index int, advancedcomponentslice *advancedcomponentslice.ComponentWithConfidenceSlice) error {
	if advancedcomponentslice.GetByIndex(index).CryptoProperties.AssetType != cdx.CryptoAssetTypeProtocol {
		return fmt.Errorf("scanner java: component of type %v cannot be used in function updateProtocolComponent", advancedcomponentslice.GetByIndex(index).CryptoProperties.AssetType)
	}

	slog.Debug("Updating protocol component", "component", advancedcomponentslice.GetByIndex(index).Name)

	switch advancedcomponentslice.GetByIndex(index).CryptoProperties.ProtocolProperties.Type {
	case cdx.CryptoProtocolTypeTLS:
		for _, cipherSuites := range *advancedcomponentslice.GetByIndex(index).CryptoProperties.ProtocolProperties.CipherSuites {
			// Test the protocol itself
			cipherSuiteConfidenceLevel, err := evalAll(&javaSecurity.tlsDisabledAlgorithms, *advancedcomponentslice.GetByIndex(index).Component)

			if err != nil {
				return err
			}

			// Test all algorithms in the protocol
			for _, algorithmRef := range *cipherSuites.Algorithms {
				algo, ok := advancedcomponentslice.GetByRef(algorithmRef)
				if ok {
					algoConfidenceLevel, err := evalAll(&javaSecurity.tlsDisabledAlgorithms, *algo.Component)

					if err != nil {
						return err
					}

					algo.Confidence.AddSubConfidenceLevel(algoConfidenceLevel, false)
					cipherSuiteConfidenceLevel.AddSubConfidenceLevel(algoConfidenceLevel, true)
					algo.SetPrintConfidenceLevel(true)
				}
			}

			advancedcomponentslice.GetByIndex(index).Confidence.AddSubConfidenceLevel(cipherSuiteConfidenceLevel, false)
		}
	}

	return nil
}

// Evaluates all JavaSecurityAlgorithmRestriction in javaSecurityAlgorithmRestrictions for component
func evalAll(javaSecurityAlgorithmRestrictions *[]JavaSecurityAlgorithmRestriction, component cdx.Component) (confidencelevel.ConfidenceLevel, error) {
	confidenceLevel := confidencelevel.New()
	var insufficientInformationErrors []error
	for _, javaSecurityAlgorithmRestriction := range *javaSecurityAlgorithmRestrictions {
		currentConfidenceLevel, err := javaSecurityAlgorithmRestriction.eval(component)

		if err != nil {
			if go_errors.Is(err, scanner_errors.ErrInsufficientInformation) {
				insufficientInformationErrors = append(insufficientInformationErrors, err)
			} else {
				return *confidenceLevel, err
			}
		}

		confidenceLevel.AddSubConfidenceLevel(currentConfidenceLevel, true)
	}

	// Did we have insufficient information with all restrictions? If so, return this.
	if len(insufficientInformationErrors) == len(*javaSecurityAlgorithmRestrictions) {
		return *confidenceLevel, go_errors.Join(insufficientInformationErrors...)
	} else {
		return *confidenceLevel, nil
	}
}

func standardizeString(in string) string {
	replacer := strings.NewReplacer("-", "", "_", "", " ", "", "/", "")
	return replacer.Replace(in)
}

// Evaluates if a single component is allowed based on a single restriction; returns true if the component is allowed, false otherwise;
// Follows the [JDK implementation]
//
// [JDK implementation]: https://github.com/openjdk/jdk/blob/master/src/java.base/share/classes/sun/security/util/DisabledAlgorithmConstraints.java
func (javaSecurityAlgorithmRestriction JavaSecurityAlgorithmRestriction) eval(component cdx.Component) (confidencelevel.ConfidenceLevel, error) {
	slog.Debug("Evaluating component with restriction", "component", component.Name, "restriction_name", javaSecurityAlgorithmRestriction.name, "restriction_operator", javaSecurityAlgorithmRestriction.keySizeOperator, "restriction_value", javaSecurityAlgorithmRestriction.keySize)

	confidenceLevel := confidencelevel.New()

	if component.CryptoProperties.AssetType != cdx.CryptoAssetTypeAlgorithm &&
		component.CryptoProperties.AssetType != cdx.CryptoAssetTypeProtocol {
		return *confidenceLevel, fmt.Errorf("scanner java: cannot evaluate components other than algorithm or protocol for applying restrictions")
	}

	// Format could be: <digest>with<encryption>and<mgf>
	replacer := strings.NewReplacer("with", " ", "and", " ")
	subAlgorithms := strings.Fields(replacer.Replace(component.Name))

	// We also need to test the full name
	if len(subAlgorithms) > 1 {
		subAlgorithms = append(subAlgorithms, component.Name)
	}

	for _, subAlgorithm := range subAlgorithms {
		restrictionStandardized, subAlgorithmStandardized := standardizeString(javaSecurityAlgorithmRestriction.name), standardizeString(subAlgorithm)
		if strings.EqualFold(restrictionStandardized, subAlgorithmStandardized) {

			confidenceLevel.Modify(confidencelevel.ConfidenceLevelModifierNegativeHigh)

			// Is the component a protocol? --> If yes, we do not have anything left to compare
			if component.CryptoProperties.AssetType == cdx.CryptoAssetTypeProtocol {
				confidenceLevel.Modify(confidencelevel.ConfidenceLevelModifierNegativeMedium)
				return *confidenceLevel, nil
			}

			// There is no need to test further if the component does not provide a keySize
			if component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier == "" {
				if javaSecurityAlgorithmRestriction.keySizeOperator != keySizeOperatorNone {
					confidenceLevel.Modify(confidencelevel.ConfidenceLevelModifierPositiveMedium)
					return *confidenceLevel, scanner_errors.GetInsufficientInformationError(fmt.Sprintf("missing key size parameter in BOM for rule affecting %v", javaSecurityAlgorithmRestriction.name), "java.security Plugin", "component", component.Name) // We actually need a keySize so we cannot go on here
				} else {
					confidenceLevel.Modify(confidencelevel.ConfidenceLevelModifierNegativeHigh)
					return *confidenceLevel, nil // Names match and we do not need a keySize --> The algorithm is not allowed!
				}
			}

			// Parsing the key size
			param, err := strconv.Atoi(component.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier)
			if err != nil {
				return *confidenceLevel, err
			}

			if param <= 0 || param > 2147483647 {
				confidenceLevel.Modify(confidencelevel.ConfidenceLevelModifierNegativeMedium)
				return *confidenceLevel, err // Following Java reference implementation (see https://github.com/openjdk/jdk/blob/4f1a10f84bcfadef263a0890b6834ccd3d5bb52f/src/java.base/share/classes/sun/security/util/DisabledAlgorithmConstraints.java#L944 and https://github.com/openjdk/jdk/blob/4f1a10f84bcfadef263a0890b6834ccd3d5bb52f/src/java.base/share/classes/sun/security/util/DisabledAlgorithmConstraints.java#L843)
			}

			var allowed bool
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
				confidenceLevel.Modify(confidencelevel.ConfidenceLevelModifierPositiveMedium)
				return *confidenceLevel, fmt.Errorf("scanner java: invalid keySizeOperator in JavaSecurityAlgorithmRestriction: %v", javaSecurityAlgorithmRestriction.keySizeOperator)
			}

			if !allowed {
				confidenceLevel.Modify(confidencelevel.ConfidenceLevelModifierNegativeMedium)
				return *confidenceLevel, err
			}
		}
	}

	return *confidenceLevel, nil
}
