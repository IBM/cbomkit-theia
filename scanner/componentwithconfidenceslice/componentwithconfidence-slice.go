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

package componentwithconfidenceslice

import (
	"github.com/IBM/cbomkit-theia/scanner/confidencelevel"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// CycloneDX component bundled with according ConfidenceLevel
type componentWithConfidence struct {
	*cdx.Component
	Confidence           *confidencelevel.ConfidenceLevel
	printConfidenceLevel bool
}

func (componentWithConfidence *componentWithConfidence) SetPrintConfidenceLevel(value bool) {
	componentWithConfidence.printConfidenceLevel = value
}

// Slice of componentWithConfidence with a map mapping BOMReference to index in the components slice; bomRefMap can be used to access members of components by BOMReference without searching for the BOMReference in the structs itself
type ComponentWithConfidenceSlice struct {
	components []componentWithConfidence
	bomRefMap  map[cdx.BOMReference]int
}

// Generate a AdvancedComponentSlice from a slice of components
func FromComponentSlice(slice []cdx.Component) *ComponentWithConfidenceSlice {
	advancedComponentSlice := ComponentWithConfidenceSlice{
		components: make([]componentWithConfidence, 0, len(slice)),
		bomRefMap:  make(map[cdx.BOMReference]int),
	}

	for i, comp := range slice {
		advancedComponentSlice.components = append(advancedComponentSlice.components, componentWithConfidence{
			Component:            &comp,
			Confidence:           confidencelevel.New(),
			printConfidenceLevel: false,
		})

		if comp.BOMRef != "" {
			advancedComponentSlice.bomRefMap[cdx.BOMReference(comp.BOMRef)] = i
		}
	}

	return &advancedComponentSlice
}

// Get member of AdvancedComponentSlice by index
func (advancedComponentSlice *ComponentWithConfidenceSlice) GetByIndex(i int) *componentWithConfidence {
	return &advancedComponentSlice.components[i]
}

// Get member of AdvancedComponentSlice by BOMReference
func (advancedComponentSlice *ComponentWithConfidenceSlice) GetByRef(ref cdx.BOMReference) (*componentWithConfidence, bool) {
	i, ok := advancedComponentSlice.bomRefMap[ref]
	if !ok {
		return &componentWithConfidence{}, false
	} else {
		return &advancedComponentSlice.components[i], true
	}
}

// Generate CycloneDX Components from this AdvancedComponentSlice; automatically sets the confidence_level property
func (advancedComponentSlice *ComponentWithConfidenceSlice) GetComponentSlice() []cdx.Component {
	finalCompSlice := make([]cdx.Component, 0, len(advancedComponentSlice.components))

	for _, compWithConf := range advancedComponentSlice.components {
		if compWithConf.printConfidenceLevel {
			addPropertyOrCreateNew(compWithConf.Component, compWithConf.Confidence.GetProperty())
		}
		finalCompSlice = append(finalCompSlice, *compWithConf.Component)
	}

	return finalCompSlice
}

func addPropertyOrCreateNew(comp *cdx.Component, prop cdx.Property) {
	if comp.Properties == nil {
		comp.Properties = new([]cdx.Property)
	}
	*comp.Properties = append(*comp.Properties, prop)
}
