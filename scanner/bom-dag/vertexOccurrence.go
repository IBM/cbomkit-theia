package bomdag

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
)

type vertexOccurrence struct {
	cdx.EvidenceOccurrence
}

func (vertexOccurrence) GetType() bomDAGVertexType {
	return BOMDAGVertexTypeOccurrence
}

func (vertexOccurrence vertexOccurrence) String() string {
	return vertexOccurrence.Location
}
