from fenrir.core.registry import discover_modules
from fenrir.core.state import Node, NodeType, StateGraph
from fenrir.modules.recon.proxy_origin_recon import ProxyOriginRecon


def test_cloudflare_headers_are_recorded_as_proxy_evidence():
    detection = ProxyOriginRecon.detect_proxy(
        {"Server": "cloudflare", "CF-RAY": "abc123-LAX", "CF-Cache-Status": "HIT"}
    )

    assert detection is not None
    assert detection["detected"] is True
    assert detection["provider"] == "cloudflare"
    assert {item["header"] for item in detection["evidence"]} >= {"server", "cf-ray"}
    assert detection["origin_confirmed"] is False


def test_candidate_deduplication_normalizes_ipv6_and_bounds_evidence():
    candidates = ProxyOriginRecon._dedupe_candidates(
        [
            {"candidate": "2001:0db8::1", "confidence": 0.35, "evidence": [{"n": 1}]},
            {"candidate": "[2001:db8:0:0:0:0:0:1]", "confidence": 0.8, "evidence": [{"n": 2}]},
        ]
    )

    assert len(candidates) == 1
    assert candidates[0]["confidence"] == 0.8
    assert len(candidates[0]["evidence"]) == 2
    assert candidates[0]["origin_confirmed"] is False


def test_proxy_origin_module_is_discoverable():
    names = {module.name for module in discover_modules()}
    assert "proxy_origin_recon" in names


def test_run_marks_attempt_and_stores_possible_candidate(monkeypatch):
    state = StateGraph()
    state.add_node(Node(NodeType.TARGET, "www.example.test", {"hostname": "www.example.test"}))
    state.add_node(
        Node(
            NodeType.SERVICE,
            "www.example.test:443/https",
            {"name": "https", "port": 443, "headers": {"CF-RAY": "ray"}},
        )
    )
    state.add_node(
        Node(NodeType.PORT, "www.example.test:443/tcp", {"host": "www.example.test", "number": 443})
    )
    monkeypatch.setattr(
        ProxyOriginRecon,
        "_resolve_hostname",
        classmethod(lambda cls, hostname: ["203.0.113.10"]),
    )
    monkeypatch.setattr(ProxyOriginRecon, "_get_tls_names", lambda self, host, port: ["origin.example.test"])

    module = ProxyOriginRecon()
    result = module.run(state)

    target = state.find(NodeType.TARGET)[0]
    assert result.success is True
    assert target.data["proxy_detection"]["provider"] == "cloudflare"
    assert target.data["origin_candidates"][0]["origin_confirmed"] is False
    assert state.find(NodeType.SERVICE)[0].data["proxy_origin_recon_attempted"] is True
    assert module.can_run(state) is False
