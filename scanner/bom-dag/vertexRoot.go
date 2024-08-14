package bomdag

type vertexRoot struct {
}

func (vertexRoot) GetType() bomDAGVertexType {
	return BOMDAGVertexTypeRoot
}

func (vertexRoot) String() string {
	return string(BOMDAGVertexTypeRoot)
}
