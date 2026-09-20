from fenrir.core.engine import Engine
from fenrir.core.state import Node, NodeType, StateGraph
from fenrir.modules.detect.http_security_headers import (
    MissingSecurityHeaders,
    MissingSecurityHeadersValidator,
)


def test_detector_creates_finding_and_validator_confirms_it():
    state = StateGraph()
    state.add_node(Node(NodeType.PORT, "host:80/tcp", {"host": "host", "number": 80}))
    state.add_node(
        Node(
            NodeType.SERVICE,
            "host:80/http",
            {
                "name": "http",
                "port": 80,
                "headers": {"Server": "test"},
            },
        )
    )

    Engine(state, [MissingSecurityHeaders(), MissingSecurityHeadersValidator()]).run()

    assert len(state.find(NodeType.FINDING, status="confirmed")) == 1
    assert "missing_security_headers_checked" not in state.get("host:80/http").data
