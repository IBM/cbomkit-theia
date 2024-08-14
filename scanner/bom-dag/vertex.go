package bomdag

import (
	"ibm/container-image-cryptography-scanner/scanner/compare"

	"github.com/dominikbraun/graph"
)

type bomDAGVertexType string

const (
	BOMDAGVertexTypeRoot       bomDAGVertexType = "root"
	BOMDAGVertexTypeComponent  bomDAGVertexType = "component"
	BOMDAGVertexTypeOccurrence bomDAGVertexType = "occurrence"
)

type bomDAGVertex interface {
	GetType() bomDAGVertexType
	String() string
}

func hashBOMDAGVertex(bomDAGVertex bomDAGVertex) BomDAGVertexHash {
	switch bomDAGVertex.GetType() {
	case BOMDAGVertexTypeComponent:
		return compare.HashCDXComponentWithoutRefs(bomDAGVertex.(vertexComponent).Component)
	case BOMDAGVertexTypeRoot:
		return BomDAGVertexHash{0}
	case BOMDAGVertexTypeOccurrence:
		return compare.HashStruct8Byte(bomDAGVertex.(vertexOccurrence))
	default:
		panic("Unsupported BOM DAG Vertex Type!")
	}
}

func getLabelForBOMDAGVertex(bomDAGVertex bomDAGVertex) func(*graph.VertexProperties) {
	return graph.VertexAttribute("label", bomDAGVertex.String())
}
