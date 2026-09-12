from pathlib import Path

from src.v20_live_bridge import LiveV20Bridge


class FakeManager:
    def get_active_incidents(self):
        return [{
            "incident_id": "NS-INC-1",
            "source_ip": "10.0.0.10",
            "destination_ip": "10.0.0.20",
            "risk_score": 85,
            "severity": "CRITICAL",
        }]


def test_live_bridge_investigation(tmp_path):
    bridge = LiveV20Bridge(log_directory=tmp_path)

    report, plan = bridge.investigate(
        {
            "incident_id": "NS-INC-1",
            "source_ip": "10.0.0.10",
            "destination_ip": "10.0.0.20",
            "risk_score": 85,
            "severity": "CRITICAL",
        },
        alerts=[{
            "alert_id": "NS-1008-1",
            "alert_type": "THREAT_INTEL",
            "rule_id": "NS-1008",
            "description": "Threat intelligence match",
            "evidence": {},
        }],
        threat_matches=[{"matched": True}],
    )

    assert report.incident_id == "NS-INC-1"
    assert plan.status == "PENDING_APPROVAL"
    assert Path(tmp_path, "incidents", "NS-INC-1",
                 "investigation_report.json").exists()


def test_active_incident_bridge(tmp_path):
    bridge = LiveV20Bridge(log_directory=tmp_path)
    results = bridge.investigate_active_incidents(
        FakeManager(),
        alert_lookup={
            "NS-INC-1": [{
                "alert_id": "A1",
                "alert_type": "PORT_SCAN",
                "rule_id": "NS-1001",
                "description": "Possible Port Scan",
                "evidence": {"ports": [22, 80]},
            }]
        },
    )

    assert len(results) == 1
    assert results[0][0].incident_id == "NS-INC-1"
    assert results[0][1].approval_required is True
