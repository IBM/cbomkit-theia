package bomdag

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
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

func hashBOMDAGVertex(bomDAGVertex bomDAGVertex) [32]byte {
	switch bomDAGVertex.GetType() {
	case BOMDAGVertexTypeComponent:
		return compare.HashCDXComponentWithoutRefs(bomDAGVertex.(vertexComponent).Component)
	case BOMDAGVertexTypeRoot:
		return sha256.Sum256([]byte{0})
	case BOMDAGVertexTypeOccurrence:
		var b bytes.Buffer
		gob.NewEncoder(&b).Encode(bomDAGVertex.(vertexOccurrence))
		return sha256.Sum256(b.Bytes())
	default:
		panic("Unsupported BOM DAG Vertex Type!")
	}
}

func getLabelForBOMDAGVertex(bomDAGVertex bomDAGVertex) func(*graph.VertexProperties) {
	return graph.VertexAttribute("label", bomDAGVertex.String())
}
