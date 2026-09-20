from fenrir.core.engine import Engine
from fenrir.core.state import Node, NodeType, StateGraph
from fenrir.modules.detect.service_exposure import (
    ServiceExposureDetector,
    ServiceExposureValidator,
)


def test_non_http_service_fingerprint_flows_to_confirmed_finding():
    state = StateGraph()
    state.add_node(Node(NodeType.PORT, "db:3306/tcp", {"host": "db", "number": 3306}))
    state.add_node(
        Node(
            NodeType.SERVICE,
            "db:3306/mysql",
            {
                "name": "mysql",
                "port": 3306,
                "mysql_server_version": "8.0.36",
            },
        )
    )

    Engine(
        state,
        [ServiceExposureDetector(), ServiceExposureValidator()],
    ).run()

    finding = state.find(NodeType.FINDING)[0]
    assert finding.data["status"] == "confirmed"
    assert finding.data["service"] == "db:3306/mysql"
