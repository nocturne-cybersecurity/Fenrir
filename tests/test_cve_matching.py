from fenrir.core.engine import Engine
from fenrir.core.state import Node, NodeType, StateGraph
from fenrir.knowledge.database import KnowledgeDatabase
from fenrir.models.vulnerability import Vulnerability
from fenrir.modules.detect.version_vulnerability import VersionVulnerabilityDetector


def test_local_knowledge_matches_service_version_without_network():
    database = KnowledgeDatabase.from_records(
        [
            Vulnerability(
                id="CVE-2099-0001",
                title="Test product vulnerability",
                affected_products=("ExampleServer",),
                affected_versions=("1.2",),
                severity="high",
                cvss=8.1,
                references=("https://example.test/advisory",),
            )
        ]
    )
    state = StateGraph()
    state.add_node(Node(NodeType.PORT, "host:80/tcp", {"host": "host", "number": 80}))
    state.add_node(
        Node(
            NodeType.SERVICE,
            "host:80/example",
            {"name": "http", "product": "ExampleServer", "version": "1.2.4", "port": 80},
        )
    )

    Engine(state, [VersionVulnerabilityDetector(database)]).run()

    finding = state.find(NodeType.FINDING)[0]
    assert finding.data["references"][0] == "CVE-2099-0001"
    assert finding.data["severity"] == "high"
