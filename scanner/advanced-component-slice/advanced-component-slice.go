package advancedcomponentslice

import (
	"ibm/container_cryptography_scanner/scanner/confidencelevel"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type componentWithConfidence struct {
	*cdx.Component
	Confidence *confidencelevel.ConfidenceLevel
}

type AdvancedComponentSlice struct {
	components []componentWithConfidence
	bomRefMap  map[cdx.BOMReference]int
}

func FromComponentSlice(slice []cdx.Component) *AdvancedComponentSlice {
	advancedComponentList := AdvancedComponentSlice{
		components: make([]componentWithConfidence, 0, len(slice)),
		bomRefMap:  make(map[cdx.BOMReference]int),
	}

	for i, comp := range slice {
		advancedComponentList.components = append(advancedComponentList.components, componentWithConfidence{
			Component:  &comp,
			Confidence: confidencelevel.New(),
		})

		if comp.BOMRef != "" {
			advancedComponentList.bomRefMap[cdx.BOMReference(comp.BOMRef)] = i
		}
	}

	return &advancedComponentList
}

func (advancedComponentList *AdvancedComponentSlice) GetByIndex(i int) *componentWithConfidence {
	return &advancedComponentList.components[i]
}

func (advancedComponentList *AdvancedComponentSlice) GetByRef(ref cdx.BOMReference) (*componentWithConfidence, bool) {
	i, ok := advancedComponentList.bomRefMap[ref]
	if !ok {
		return &componentWithConfidence{}, false
	} else {
		return &advancedComponentList.components[i], true
	}
}

func (advancedComponentList *AdvancedComponentSlice) GetComponentSlice() []cdx.Component {
	finalCompSlice := make([]cdx.Component, 0, len(advancedComponentList.components))

	for _, compWithConf := range advancedComponentList.components {
		addPropertyOrCreateNew(compWithConf.Component, compWithConf.Confidence.GetProp())
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
