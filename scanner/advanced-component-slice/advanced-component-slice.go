package advancedcomponentslice

import (
	"ibm/container-image-cryptography-scanner/scanner/confidencelevel"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// CycloneDX component bundled with according ConfidenceLevel
type componentWithConfidence struct {
	*cdx.Component
	Confidence *confidencelevel.ConfidenceLevel
	printConfidenceLevel bool
}

func (componentWithConfidence *componentWithConfidence) SetPrintConfidenceLevel(value bool) {
	componentWithConfidence.printConfidenceLevel = value
}

// Slice of componentWithConfidence with a map mapping BOMReference to index in the components slice; bomRefMap can be used to access members of components by BOMReference without searching for the BOMReference in the structs itself
type AdvancedComponentSlice struct {
	components []componentWithConfidence
	bomRefMap  map[cdx.BOMReference]int
}

// Generate a AdvancedComponentSlice from a slice of components
func FromComponentSlice(slice []cdx.Component) *AdvancedComponentSlice {
	advancedComponentSlice := AdvancedComponentSlice{
		components: make([]componentWithConfidence, 0, len(slice)),
		bomRefMap:  make(map[cdx.BOMReference]int),
	}

	for i, comp := range slice {
		advancedComponentSlice.components = append(advancedComponentSlice.components, componentWithConfidence{
			Component:  &comp,
			Confidence: confidencelevel.New(),
			printConfidenceLevel: false,
		})

		if comp.BOMRef != "" {
			advancedComponentSlice.bomRefMap[cdx.BOMReference(comp.BOMRef)] = i
		}
	}

	return &advancedComponentSlice
}

// Get member of AdvancedComponentSlice by index
func (advancedComponentSlice *AdvancedComponentSlice) GetByIndex(i int) *componentWithConfidence {
	return &advancedComponentSlice.components[i]
}

// Get member of AdvancedComponentSlice by BOMReference
func (advancedComponentSlice *AdvancedComponentSlice) GetByRef(ref cdx.BOMReference) (*componentWithConfidence, bool) {
	i, ok := advancedComponentSlice.bomRefMap[ref]
	if !ok {
		return &componentWithConfidence{}, false
	} else {
		return &advancedComponentSlice.components[i], true
	}
}

// Generate CycloneDX Components from this AdvancedComponentSlice; automatically sets the cics_confidence_level property
func (advancedComponentSlice *AdvancedComponentSlice) GetComponentSlice() []cdx.Component {
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
