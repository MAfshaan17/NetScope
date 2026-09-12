from pathlib import Path

from src.analyzer import packet_matches, is_private_ip, get_direction
from src.v20_live_bridge import LiveV20Bridge


def test_analyzer_import_is_safe():
    assert callable(packet_matches)
    assert callable(is_private_ip)
    assert callable(get_direction)


def test_v20_bridge_creates_investigation(tmp_path):
    bridge = LiveV20Bridge(log_directory=str(tmp_path))

    incident = {
        "incident_id": "NS-INC-LIVE-1",
        "source_ip": "10.0.0.10",
        "destination_ip": "10.0.0.20",
        "risk_score": 85,
        "severity": "CRITICAL",
    }

    alerts = [{
        "alert_id": "NS-1008-LIVE",
        "alert_type": "THREAT_INTELLIGENCE",
        "rule_id": "NS-1008",
        "severity": "CRITICAL",
        "source_ip": "10.0.0.10",
        "destination_ip": "10.0.0.20",
        "description": "Malicious IOC match",
        "evidence": {"classification": "MALICIOUS"},
    }]

    report, plan = bridge.investigate(
        incident=incident,
        alerts=alerts,
        threat_matches=[{"matched": True, "classification": "MALICIOUS"}],
    )

    assert report.incident_id == "NS-INC-LIVE-1"
    assert report.risk_score == 85
    assert plan.status == "PENDING_APPROVAL"

    incident_dir = Path(tmp_path) / "incidents" / "NS-INC-LIVE-1"
    assert (incident_dir / "investigation_report.json").exists()
    assert (incident_dir / "response_plan.json").exists()
    assert (incident_dir / "manifest.json").exists()
