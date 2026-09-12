from pathlib import Path

from src.investigation_engine import InvestigationEngine
from src.response_engine import ResponseEngine
from src.evidence_manager import EvidenceManager
from src.v20_soc import V20SOC


def alert(rule, aid, desc="test"):
    return {
        "rule_id": rule,
        "alert_id": aid,
        "alert_type": rule,
        "severity": "HIGH",
        "source_ip": "10.0.0.10",
        "destination_ip": "10.0.0.20",
        "description": desc,
        "evidence": {"ports": [22, 80], "protocol": "TCP"},
    }


def incident():
    return {
        "incident_id": "NS-INC-9000",
        "source_ip": "10.0.0.10",
        "destination_ip": "10.0.0.20",
        "risk_score": 85,
        "severity": "CRITICAL",
    }


def test_investigation_report():
    engine = InvestigationEngine()
    report = engine.investigate(
        incident(),
        alerts=[
            alert("PORT_SCAN", "NS-1"),
            alert("SYN_SCAN", "NS-2"),
        ],
        threat_matches=[{"matched": True}],
    )
    assert report.risk_score == 85
    assert len(report.alert_ids) == 2
    assert report.evidence["threat_intel_match_count"] == 1
    assert "BLOCK_SOURCE_IP" in report.recommended_actions


def test_response_requires_approval():
    report = InvestigationEngine().investigate(incident())
    plan = ResponseEngine().create_plan(report)
    assert plan.approval_required is True
    assert plan.status == "PENDING_APPROVAL"


def test_approval_flow():
    report = InvestigationEngine().investigate(incident())
    plan = ResponseEngine().create_plan(report)
    approved = ResponseEngine.approve(plan)
    assert approved["status"] == "APPROVED"
    assert approved["approval_required"] is False


def test_evidence_manager(tmp_path):
    manager = EvidenceManager(tmp_path)
    path = manager.save_incident_evidence(
        incident_id="NS-INC-1",
        incident=incident(),
        investigation=InvestigationEngine().investigate(incident()),
        response_plan=ResponseEngine().create_plan(
            InvestigationEngine().investigate(incident())
        ),
        alerts=[],
        flows=[],
    )
    directory = Path(path)
    assert (directory / "incident.json").exists()
    assert (directory / "investigation_report.json").exists()
    assert (directory / "response_plan.json").exists()
    assert (directory / "manifest.json").exists()


def test_v20_soc_end_to_end(tmp_path):
    soc = V20SOC(tmp_path)
    report, plan = soc.investigate_incident(
        incident(),
        alerts=[alert("THREAT_INTEL", "NS-1008")],
        threat_matches=[{"matched": True}],
    )
    assert report.incident_id == "NS-INC-9000"
    assert plan.status == "PENDING_APPROVAL"
    assert soc.get_summary()["investigations"] == 1
