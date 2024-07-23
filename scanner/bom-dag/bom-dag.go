package bomdag

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/dominikbraun/graph"
)

type BomDAG struct {
	graph.Graph[[32]byte, cdx.Component]
	Root [32]byte
}

func hashComponent(comp cdx.Component) [32]byte {
	var b bytes.Buffer
	gob.NewEncoder(&b).Encode(comp)
	return sha256.Sum256(b.Bytes())
}

func NewBomDAG() BomDAG {
	rootComponent := cdx.Component{}
	rootHash := hashComponent(rootComponent)
	graph := graph.New(hashComponent, graph.Acyclic(), graph.Directed(), graph.PreventCycles(), graph.Rooted())
	graph.AddVertex(rootComponent)
	return BomDAG{
		Graph: graph,
		Root: rootHash,
	}
}

type BomDAGDependencyType string

const (
	BomDAGDependencyTypeDependsOn                                            BomDAGDependencyType = "dependsOn"
	BomDAGDependencyTypeCertificatePropertiesSignatureAlgorithmRef           BomDAGDependencyType = "CertificateProperties.SignatureAlgorithmRef"
	BomDAGDependencyTypeCertificatePropertiesSubjectPublicKeyRef             BomDAGDependencyType = "CertificateProperties.SubjectPublicKeyRef"
	BomDAGDependencyTypeRelatedCryptoMaterialPropertiesAlgorithmRef          BomDAGDependencyType = "RelatedCryptoMaterialProperties.AlgorithmRef"
	BomDAGDependencyTypeRelatedCryptoMaterialPropertiesSecuredByAlgorithmRef BomDAGDependencyType = "RelatedCryptoMaterialProperties.securedBy.AlgorithmRef"
	BomDAGDependencyTypeProtocolPropertiesCryptoRefArrayElement              BomDAGDependencyType = "protocolProperties.cryptoRefArray"
)

func EdgeDependencyType(dependencyType BomDAGDependencyType) func(*graph.EdgeProperties) {
	return func(e *graph.EdgeProperties) {
		e.Attributes[string(dependencyType)] = ""
	}
}

func (bomDAG *BomDAG) GetCDXComponents() ([]cdx.Component, map[cdx.BOMReference][]string, error) {
	components := make([]cdx.Component, 0)
	dependencyMap := make(map[cdx.BOMReference][]string, 0)

	adjacencyMap, err := bomDAG.AdjacencyMap()

	if err != nil {
		return components, dependencyMap, err
	}

	for compHash, compOutgoingEdges := range adjacencyMap {
		if compHash == bomDAG.Root {
			continue
		}
		component, _ := bomDAG.Vertex(compHash)
		component.BOMRef = hex.EncodeToString(compHash[:])
		dependencyMap[cdx.BOMReference(component.BOMRef)] = make([]string, 0)

		for _, edge := range compOutgoingEdges {
			targetBomRef := cdx.BOMReference(hex.EncodeToString(edge.Target[:]))
			for edgeType, _ := range edge.Properties.Attributes {
				switch edgeType {
				case string(BomDAGDependencyTypeDependsOn):
					dependencyMap[cdx.BOMReference(component.BOMRef)] = append(dependencyMap[cdx.BOMReference(component.BOMRef)], string(targetBomRef))
				case string(BomDAGDependencyTypeCertificatePropertiesSignatureAlgorithmRef):
					component.CryptoProperties.CertificateProperties.SignatureAlgorithmRef = targetBomRef
				case string(BomDAGDependencyTypeCertificatePropertiesSubjectPublicKeyRef):
					component.CryptoProperties.CertificateProperties.SubjectPublicKeyRef = targetBomRef
				case string(BomDAGDependencyTypeRelatedCryptoMaterialPropertiesAlgorithmRef):
					component.CryptoProperties.RelatedCryptoMaterialProperties.AlgorithmRef = targetBomRef
				case string(BomDAGDependencyTypeRelatedCryptoMaterialPropertiesSecuredByAlgorithmRef):
					component.CryptoProperties.RelatedCryptoMaterialProperties.SecuredBy.AlgorithmRef = targetBomRef
				case string(BomDAGDependencyTypeProtocolPropertiesCryptoRefArrayElement):
					if component.CryptoProperties.ProtocolProperties.CryptoRefArray == nil {
						component.CryptoProperties.ProtocolProperties.CryptoRefArray = new([]cdx.BOMReference)
					}
					*component.CryptoProperties.ProtocolProperties.CryptoRefArray = append(*component.CryptoProperties.ProtocolProperties.CryptoRefArray, targetBomRef)
				}
			}
		}
		components = append(components, component)
	}

	return components, dependencyMap, nil
}

func (bomDAG *BomDAG) Merge(other BomDAG) error {
	adjacencyMap, err := other.AdjacencyMap()
	if err != nil {
		return fmt.Errorf("failed to get adjacency map: %w", err)
	}

	for hash := range adjacencyMap {
		vertex, properties, err := other.VertexWithProperties(hash)
		if err != nil {
			return fmt.Errorf("failed to get vertex %v: %w", hash, err)
		}

		if err = bomDAG.AddVertex(vertex, copyVertexProperties(properties)); err != nil {
			continue
		}
	}

	edges, err := other.Edges()
	if err != nil {
		return fmt.Errorf("failed to get edges: %w", err)
	}

	for _, otherEdge := range edges {
		if err := bomDAG.AddEdge(copyEdge(otherEdge)); err == graph.ErrEdgeAlreadyExists {
			if err := bomDAG.mergeEdgePropertyAttributes(otherEdge); err != nil {
				return fmt.Errorf("failed to add (%v, %v): %w", otherEdge.Source, otherEdge.Target, err)
			}
		} else if err != nil {
			return fmt.Errorf("failed to add (%v, %v): %w", otherEdge.Source, otherEdge.Target, err)
		}
	}

	return nil
}

func (bomDAG *BomDAG) mergeEdgePropertyAttributes(otherEdge graph.Edge[[32]byte]) error {
	mainEdge, err := bomDAG.Edge(otherEdge.Source, otherEdge.Target)

	if err != nil {
		return err
	}

	if mainEdge.Properties.Data != otherEdge.Properties.Data ||
		mainEdge.Properties.Weight != otherEdge.Properties.Weight {
		return fmt.Errorf("both edges should have the same source, target, data and weight to merge their edge attributes")
	}

	for key, otherValue := range otherEdge.Properties.Attributes {
		mainValue, ok := mainEdge.Properties.Attributes[key]
		if ok {
			if mainValue != otherValue {
				return fmt.Errorf("attribute %v cannot be merged (both are set and cannot merge strings); mainValue: %v, otherValue: %v", key, mainValue, otherValue)
			}
		} else {
			bomDAG.UpdateEdge(otherEdge.Source, otherEdge.Target, graph.EdgeAttribute(key, otherValue))
		}
	}

	return nil
}

func copyEdge[K comparable](edge graph.Edge[K]) (K, K, func(properties *graph.EdgeProperties)) {
	copyProperties := func(p *graph.EdgeProperties) {
		for k, v := range edge.Properties.Attributes {
			p.Attributes[k] = v
		}
		p.Weight = edge.Properties.Weight
		p.Data = edge.Properties.Data
	}

	return edge.Source, edge.Target, copyProperties
}

func copyVertexProperties(source graph.VertexProperties) func(*graph.VertexProperties) {
	return func(p *graph.VertexProperties) {
		for k, v := range source.Attributes {
			p.Attributes[k] = v
		}
		p.Weight = source.Weight
	}
}

func (bomDAG *BomDAG) GetVertexOrAddNew(value cdx.Component, options ...func(*graph.VertexProperties)) (hash [32]byte, err error) {
	hash = hashComponent(value)

	// Does the component already exist?
	if _, err := bomDAG.Vertex(hash); err != graph.ErrVertexNotFound {
		return hash, nil
	}

	err = bomDAG.AddVertex(value, options...)
	return hash, err
}
