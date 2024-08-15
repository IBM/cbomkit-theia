package bomdag

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/dominikbraun/graph"
	"github.com/dominikbraun/graph/draw"
)

type BomDAGVertexHash = [8]byte

type BomDAG struct {
	graph.Graph[BomDAGVertexHash, bomDAGVertex]
	Root BomDAGVertexHash
}

func NewBomDAG() BomDAG {
	rootComponent := vertexRoot{}
	rootHash := hashBOMDAGVertex(rootComponent)
	g := graph.New(hashBOMDAGVertex, graph.Acyclic(), graph.Directed(), graph.PreventCycles(), graph.Rooted())
	g.AddVertex(rootComponent, getLabelForBOMDAGVertex(rootComponent))
	return BomDAG{
		Graph: g,
		Root:  rootHash,
	}
}

type BomDAGDependencyType string

const (
	BomDAGDependencyTypeDependsOn                                            BomDAGDependencyType = "dependsOn"
	BomDAGDependencyTypeCertificatePropertiesSignatureAlgorithmRef           BomDAGDependencyType = "CertificatePropertiesSignatureAlgorithmRef"
	BomDAGDependencyTypeCertificatePropertiesSubjectPublicKeyRef             BomDAGDependencyType = "CertificatePropertiesSubjectPublicKeyRef"
	BomDAGDependencyTypeRelatedCryptoMaterialPropertiesAlgorithmRef          BomDAGDependencyType = "RelatedCryptoMaterialPropertiesAlgorithmRef"
	BomDAGDependencyTypeRelatedCryptoMaterialPropertiesSecuredByAlgorithmRef BomDAGDependencyType = "RelatedCryptoMaterialPropertiessecuredByAlgorithmRef"
	BomDAGDependencyTypeProtocolPropertiesCryptoRefArrayElement              BomDAGDependencyType = "protocolPropertiescryptoRefArray"
	BomDAGDependencyTypeOccurrence                                           BomDAGDependencyType = "occurrence"
)

func EdgeDependencyType(dependencyType BomDAGDependencyType) func(*graph.EdgeProperties) {
	return func(e *graph.EdgeProperties) {
		e.Attributes[string(dependencyType)] = ""
		if _, ok := e.Attributes["label"]; !ok {
			e.Attributes["label"] = string(dependencyType)
		} else {
			e.Attributes["label"] = fmt.Sprintf("%v; %v", e.Attributes["label"], string(dependencyType))
		}
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
		bomDAGVertex, _ := bomDAG.Vertex(compHash)

		if bomDAGVertex.GetType() != BOMDAGVertexTypeComponent {
			continue
		}

		component := bomDAGVertex.(vertexComponent).Component

		component.BOMRef = hex.EncodeToString(compHash[:])

		for _, edge := range compOutgoingEdges {
			targetBomRef := cdx.BOMReference(hex.EncodeToString(edge.Target[:]))
			for edgeType := range edge.Properties.Attributes {
				switch edgeType {
				case string(BomDAGDependencyTypeDependsOn):
					if _, ok := dependencyMap[cdx.BOMReference(component.BOMRef)]; !ok {
						dependencyMap[cdx.BOMReference(component.BOMRef)] = make([]string, 0)
					}
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
				case string(BomDAGDependencyTypeOccurrence):
					targetVertex, _ := bomDAG.Vertex(edge.Target)
					*component.Evidence.Occurrences = append(*component.Evidence.Occurrences, targetVertex.(vertexOccurrence).EvidenceOccurrence)
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

func (bomDAG *BomDAG) mergeEdgePropertyAttributes(otherEdge graph.Edge[BomDAGVertexHash]) error {
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

func (bomDAG *BomDAG) AddCDXComponent(value cdx.Component, options ...func(*graph.VertexProperties)) (valueHash BomDAGVertexHash, err error) {
	// Extract the occurrence component
	var occurrenceHashes []BomDAGVertexHash
	if value.Evidence != nil && value.Evidence.Occurrences != nil && len(*value.Evidence.Occurrences) > 0 {
		occurrenceHashes = make([]BomDAGVertexHash, len(*value.Evidence.Occurrences))
		for i, occurrence := range *value.Evidence.Occurrences {
			hash, err := bomDAG.getVertexOrAddNew(vertexOccurrence{occurrence})
			if err != nil {
				return BomDAGVertexHash{}, err
			}
			occurrenceHashes[i] = hash
		}

		// Clean it all up
		value.Evidence.Occurrences = new([]cdx.EvidenceOccurrence)
	}

	// Create the component and link to occurrences
	valueHash, err = bomDAG.getVertexOrAddNew(vertexComponent{value}, options...)
	if err != nil {
		return valueHash, err
	}

	for _, occurrenceHash := range occurrenceHashes {
		bomDAG.AddEdge(valueHash, occurrenceHash, EdgeDependencyType(BomDAGDependencyTypeOccurrence))
	}

	return valueHash, nil
}

func (bomDAG *BomDAG) getVertexOrAddNew(value bomDAGVertex, options ...func(*graph.VertexProperties)) (hash BomDAGVertexHash, err error) {
	hash = hashBOMDAGVertex(value)

	// Does the component already exist?
	_, err = bomDAG.Vertex(hash)
	if err != graph.ErrVertexNotFound {
		return hash, nil
	}

	err = bomDAG.AddVertex(value, append(options, getLabelForBOMDAGVertex(value))...)
	return hash, err
}

func (bomDAG *BomDAG) WriteToFile(filesystemIdentifier string) {
	if err := os.MkdirAll(filepath.Join(".", "cics_graphs"), os.ModePerm); err != nil {
		slog.Warn("Failed to create directory for graphs. Skipping this step.", "error", err.Error())
	} else {
		file, err := os.Create(filepath.Join(".", "cics_graphs", url.PathEscape(fmt.Sprintf("%v_certificate_graph.dot", filesystemIdentifier))))
		if err != nil {
			slog.Warn("Failed to generate DOT file for graph", "error", err.Error())
		}
		err = draw.DOT(bomDAG, file)
		if err != nil {
			slog.Warn("Failed to write to DOT file for graph", "error", err.Error())
		}
	}
}
