"""
NetScope V1.8.7 SOC integration tests.
"""

from src.incident_manager import IncidentManager
from src.soc_controller import SOCController


def make_alert(
    alert_id,
    rule_id,
    source="10.0.0.10",
    destination="10.0.0.20",
    severity="HIGH",
):
    return {
        "alert_id": alert_id,
        "rule_id": rule_id,
        "alert_type": rule_id,
        "source_ip": source,
        "destination_ip": destination,
        "severity": severity,
        "description": f"Test {rule_id}",
        "evidence": {"ports": [80, 443]},
        "timestamp": "2026-09-12T02:00:00",
    }


def test_full_soc_pipeline(tmp_path):
    controller = SOCController(
        log_directory=str(tmp_path)
    )

    alerts = [
        make_alert("A-001", "NS-1001"),
        make_alert("A-002", "NS-1002"),
        make_alert("A-003", "NS-1005"),
    ]

    incidents = controller.process_alerts(
        alerts,
        risk_score=75,
    )

    assert len(incidents) == 3
    assert len(controller.incident_manager.incidents) == 1

    incident = controller.incident_manager.incidents[0]

    assert incident.risk_score == 75
    assert incident.severity == "HIGH"
    assert len(incident.alert_ids) == 3

    assert len(controller.timeline.get_events()) == 3
    assert "RECONNAISSANCE" in controller.timeline.get_attack_stages()
    assert "SCANNING" in controller.timeline.get_attack_stages()
    assert "CONNECTION_FLOOD" in controller.timeline.get_attack_stages()

    attacker = controller.profile_engine.get_attacker(
        "10.0.0.10"
    )
    victim = controller.profile_engine.get_victim(
        "10.0.0.20"
    )

    assert attacker.alert_count == 3
    assert attacker.incident_count == 1
    assert victim.attack_count == 3
    assert victim.incident_count == 1


def test_duplicate_alert_is_not_processed(tmp_path):
    controller = SOCController(
        log_directory=str(tmp_path)
    )

    alert = make_alert("A-100", "NS-1001")

    controller.process_alerts([alert], risk_score=50)
    controller.process_alerts([alert], risk_score=50)

    incident = controller.incident_manager.incidents[0]

    assert len(controller.incident_manager.incidents) == 1
    assert incident.alert_ids.count("A-100") == 1

    attacker = controller.profile_engine.get_attacker(
        "10.0.0.10"
    )
    assert attacker.alert_count == 1


def test_soc_persistence(tmp_path):
    controller = SOCController(
        log_directory=str(tmp_path)
    )

    controller.process_alerts(
        [make_alert("A-200", "NS-1007", severity="CRITICAL")],
        risk_score=90,
    )
    controller.save()

    restored = SOCController(
        log_directory=str(tmp_path)
    )

    assert len(restored.incident_manager.incidents) == 1

    attacker = restored.profile_engine.get_attacker(
        "10.0.0.10"
    )
    victim = restored.profile_engine.get_victim(
        "10.0.0.20"
    )

    assert attacker.alert_count == 1
    assert attacker.incident_count == 1
    assert victim.attack_count == 1
    assert victim.incident_count == 1


def test_multiple_attackers_create_separate_incidents(tmp_path):
    controller = SOCController(
        log_directory=str(tmp_path)
    )

    controller.process_alerts([
        make_alert(
            "A-301",
            "NS-1001",
            source="10.0.0.1",
            destination="10.0.0.20",
        ),
        make_alert(
            "A-302",
            "NS-1001",
            source="10.0.0.2",
            destination="10.0.0.20",
        ),
    ])

    assert len(controller.incident_manager.incidents) == 2
    assert len(controller.profile_engine.attackers) == 2


def test_soc_summary(tmp_path):
    controller = SOCController(
        log_directory=str(tmp_path)
    )

    controller.process_alerts(
        [make_alert("A-401", "NS-1004")],
        risk_score=30,
    )

    summary = controller.get_summary()

    assert summary["incidents"] == 1
    assert summary["active_incidents"] == 1
    assert summary["attackers"] == 1
    assert summary["victims"] == 1
    assert summary["timeline_events"] == 1
