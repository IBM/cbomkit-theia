package bomdag

import (
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type vertexComponent struct {
	cdx.Component
}

func (vertexComponent) GetType() bomDAGVertexType {
	return BOMDAGVertexTypeComponent
}

func (vertexComponent vertexComponent) String() string {
	label := vertexComponent.Name
	if vertexComponent.CryptoProperties != nil {
		label = fmt.Sprintf("%v (%v)", label, string(vertexComponent.CryptoProperties.AssetType))
		if vertexComponent.CryptoProperties.RelatedCryptoMaterialProperties != nil {
			label = fmt.Sprintf("%v (%v)", label, string(vertexComponent.CryptoProperties.RelatedCryptoMaterialProperties.Type))
		}
	}

	return label
}
