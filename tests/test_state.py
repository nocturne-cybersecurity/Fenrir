from fenrir.core.state import Node, NodeType, StateGraph


def test_add_node_merges_data():
    s = StateGraph()
    s.add_node(Node(NodeType.HOST, "10.0.0.1", {"ip": "10.0.0.1"}))
    s.add_node(Node(NodeType.HOST, "10.0.0.1", {"os": "linux"}))
    assert len(s.find(NodeType.HOST)) == 1
    assert s.get("10.0.0.1").data["os"] == "linux"


def test_find_with_filters():
    s = StateGraph()
    s.add_node(Node(NodeType.SERVICE, "a", {"name": "http", "port": 80}))
    s.add_node(Node(NodeType.SERVICE, "b", {"name": "ssh", "port": 22}))
    assert len(s.find(NodeType.SERVICE, name="http")) == 1
    assert s.has(NodeType.SERVICE, port=22)