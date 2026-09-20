from __future__ import annotations

import struct

from fenrir.core.registry import discover_modules
from fenrir.core.state import Node, NodeType, StateGraph
from fenrir.modules.enum.ldap_enum import LDAPEnum
from fenrir.modules.enum.memcached_enum import MemcachedEnum
from fenrir.modules.enum.mongodb_enum import MongoDBEnum
from fenrir.modules.enum.mysql_enum import MySQLEnum
from fenrir.modules.enum.postgresql_enum import PostgreSQLEnum
from fenrir.modules.enum.redis_enum import RedisEnum


def test_database_modules_are_discovered_once():
    modules = discover_modules()
    names = [module.name for module in modules]
    assert {"mysql_enum", "postgresql_enum", "redis_enum", "mongodb_enum"} <= set(names)
    assert {"memcached_enum", "ldap_enum"} <= set(names)
    assert len(names) == len(set(names))


def test_mysql_greeting_parser_extracts_server_metadata():
    payload = (
        b"\x0a8.0.36\x00"
        + struct.pack("<I", 7)
        + b"abcdefgh\x00"
        + struct.pack("<H", 0xFFFF)
        + bytes([33])
        + struct.pack("<H", 2)
        + struct.pack("<H", 0x000F)
        + bytes([21])
        + b"\x00" * 10
        + b"ijklmnop\x00mysql_native_password\x00"
    )
    parsed = MySQLEnum.parse_greeting(payload)
    assert parsed["mysql_server_version"] == "8.0.36"
    assert parsed["mysql_charset"] == 33
    assert parsed["mysql_auth_plugin"] == "mysql_native_password"


def test_postgresql_packets_use_protocol_constants():
    ssl_request = PostgreSQLEnum.build_ssl_request()
    assert struct.unpack("!II", ssl_request) == (8, 80877103)
    startup = PostgreSQLEnum.build_startup_packet()
    assert struct.unpack("!II", startup[:8]) == (len(startup), 196608)
    assert b"user\x00fenrir\x00" in startup


def test_redis_command_and_info_parser():
    assert RedisEnum.build_command("PING") == b"*1\r\n$4\r\nPING\r\n"
    parsed = RedisEnum.parse_info("# Server\nredis_version:7.2.1\nos:Linux\n")
    assert parsed["redis_version"] == "7.2.1"
    assert parsed["redis_os"] == "Linux"


def test_mongodb_and_ldap_packets_are_well_formed():
    packet = MongoDBEnum.build_op_msg(12)
    length, request_id, _, opcode = struct.unpack("<iiii", packet[:16])
    assert length == len(packet)
    assert request_id == 12
    assert opcode == 2013
    bind = LDAPEnum.build_anonymous_bind()
    assert bind.startswith(b"\x30") and b"\x60" in bind


def test_memcached_version_parser():
    assert MemcachedEnum.parse_version("VERSION 1.6.21\r\n") == {
        "memcached_banner": "VERSION 1.6.21",
        "memcached_version": "1.6.21",
    }


def test_failed_attempt_is_marked_and_not_repeated(monkeypatch):
    state = StateGraph()
    state.add_node(
        Node(NodeType.PORT, "127.0.0.1:3306/tcp", {"host": "127.0.0.1", "number": 3306})
    )
    state.add_node(Node(NodeType.SERVICE, "db", {"name": "mysql", "port": 3306}))
    monkeypatch.setattr(MySQLEnum, "_grab", staticmethod(lambda host, port: b"invalid"))
    module = MySQLEnum()
    assert module.can_run(state)
    result = module.run(state)
    service = state.get("db")
    assert result.success
    assert service is not None and service.data["mysql_checked"] is True
    assert not module.can_run(state)
