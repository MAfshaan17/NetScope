"""
V1.9.3 Live SOC Pipeline tests.

These tests validate orchestration without requiring a real network
interface. They use Scapy packets and the real project engines.
"""

from scapy.all import IP, TCP, UDP

from src.analyzer import (
    get_direction,
    is_private_ip,
    packet_matches,
)


class Args:
    protocol = None
    ip = None
    port = None


def test_private_ip_detection():
    assert is_private_ip("10.0.0.1")
    assert is_private_ip("192.168.1.10")
    assert is_private_ip("172.16.0.1")
    assert not is_private_ip("8.8.8.8")


def test_direction():
    assert get_direction(
        "10.0.0.10",
        "8.8.8.8",
    ) == "OUTBOUND"

    assert get_direction(
        "8.8.8.8",
        "10.0.0.10",
    ) == "INBOUND"

    assert get_direction(
        "10.0.0.10",
        "10.0.0.20",
    ) == "LOCAL"


def test_packet_filter_protocol():
    args = Args()
    args.protocol = "tcp"

    packet = (
        IP(
            src="10.0.0.10",
            dst="10.0.0.20",
        )
        / TCP(
            sport=50000,
            dport=443,
        )
    )

    assert packet_matches(packet, args)


def test_packet_filter_port():
    args = Args()
    args.protocol = None
    args.port = 443

    packet = (
        IP(
            src="10.0.0.10",
            dst="10.0.0.20",
        )
        / TCP(
            sport=50000,
            dport=443,
        )
    )

    assert packet_matches(packet, args)


def test_packet_filter_ip_both_directions():
    args = Args()
    args.protocol = None
    args.port = None
    args.ip = "10.0.0.20"

    outbound = (
        IP(
            src="10.0.0.10",
            dst="10.0.0.20",
        )
        / UDP(
            sport=50000,
            dport=53,
        )
    )

    inbound = (
        IP(
            src="10.0.0.20",
            dst="10.0.0.10",
        )
        / UDP(
            sport=53,
            dport=50000,
        )
    )

    assert packet_matches(outbound, args)
    assert packet_matches(inbound, args)


def test_non_ip_packet_is_ignored():
    from scapy.all import Ether, ARP

    args = Args()

    packet = Ether() / ARP()

    assert not packet_matches(packet, args)
