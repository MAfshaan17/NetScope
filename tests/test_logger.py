import json

from src.logger import NetScopeLogger
from src.models import SecurityAlert


def test_packet_logging(tmp_path):

    logger = NetScopeLogger(tmp_path)

    packets = [
        {
            "source_ip": "10.0.0.1",
            "destination_ip": "8.8.8.8",
            "protocol": "UDP"
        }
    ]

    logger.log_packets(packets)

    file = tmp_path / "packets.json"

    assert file.exists()

    data = json.loads(
        file.read_text(encoding="utf-8")
    )

    assert len(data) == 1
    assert data[0]["protocol"] == "UDP"


def test_alert_logging(tmp_path):

    logger = NetScopeLogger(tmp_path)

    alert = SecurityAlert(
        alert_type="Possible SYN Scan",
        severity="HIGH",
        rule_id="NS-1002",
        source_ip="192.168.1.100",
        destination_ip="192.168.1.200",
        description="Test SYN scan",
        evidence={
            "ports": [21, 22, 23]
        },
        confidence=92
    )

    logger.log_alerts([alert])

    file = tmp_path / "security_alerts.json"

    assert file.exists()

    data = json.loads(
        file.read_text(encoding="utf-8")
    )

    assert data[0]["rule_id"] == "NS-1002"
    assert data[0]["severity"] == "HIGH"
    assert data[0]["confidence"] == 92