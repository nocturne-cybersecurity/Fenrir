from fenrir.core.registry import discover_modules
from fenrir.core.state import Node, NodeType, StateGraph
from fenrir.modules.enum.smb_enum import SMBEnum
from fenrir.modules.enum.web_enum import _HTMLMetadataParser
from fenrir.modules.recon.dns_recon import DNSRecon
from fenrir.modules.recon.host_discovery import HostDiscovery


def test_discover_modules_includes_passive_modules():
    modules = discover_modules()
    names = {module.name for module in modules}
    expected = {
        "ftp_enum",
        "smb_enum",
        "dns_enum",
        "web_enum",
        "host_discovery",
        "dns_recon",
    }
    assert expected.issubset(names)
    assert len(modules) == len(names)


def test_host_discovery_resolves_ip_literal():
    assert HostDiscovery._resolve("127.0.0.1") == ["127.0.0.1"]


def test_dns_recon_parses_getent_output():
    text = "10.0.0.5 example.com\n10.0.0.6 test.example.com\n"
    assert DNSRecon._parse_getent(text) == ["10.0.0.5", "10.0.0.6"]


def test_web_parser_extracts_title_and_forms():
    parser = _HTMLMetadataParser()
    parser.feed(
        "<html><head><title>Example</title>"
        "<meta name='generator' content='Fenrir'>"
        "<link rel='stylesheet' href='/style.css'>"
        "</head><body><a href='/about'>About</a>"
        "<form action='/login' method='post'></form></body></html>"
    )
    assert parser.title == "Example"
    assert parser.meta["generator"] == "Fenrir"
    assert parser.forms[0]["action"] == "/login"
    assert parser.forms[0]["method"] == "POST"


def test_smb_enum_parses_negotiate_banner():
    payload = b"\xffSMB\x72\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    parsed = SMBEnum._parse_banner(payload.decode("latin-1", errors="ignore"))
    assert parsed["smb_magic"] == "SMB"
    assert parsed["smb_negotiation"].startswith("ff534d42")


def test_state_graph_accepts_service_metadata():
    state = StateGraph()
    state.add_node(Node(NodeType.SERVICE, "svc-a", {"name": "http", "port": 80}))
    state.add_node(Node(NodeType.PORT, "10.0.0.1:80/tcp", {"host": "10.0.0.1", "number": 80}))
    service = state.find(NodeType.SERVICE, name="http")[0]
    assert service.data["port"] == 80
