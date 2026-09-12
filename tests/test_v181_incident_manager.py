from src.incident_manager import IncidentManager


def test_create_incident(tmp_path):

    manager = IncidentManager(
        log_directory=str(tmp_path)
    )

    incident = manager.create_incident(
        source_ip="10.0.0.10",
        destination_ip="10.0.0.20",
        severity="HIGH",
        risk_score=65,
        attack_type="PORT_SCAN",
        alert_id="NS-1001",
        evidence={
            "unique_ports": 20
        },
    )

    assert incident.incident_id == "NS-INC-0001"

    assert incident.severity == "HIGH"

    assert incident.risk_score == 65

    assert incident.source_ip == "10.0.0.10"

    assert incident.destination_ip == "10.0.0.20"

    assert incident.status == "OPEN"

    assert "PORT_SCAN" in incident.attack_types

    assert "NS-1001" in incident.alert_ids


def test_add_alert_to_incident(tmp_path):

    manager = IncidentManager(
        log_directory=str(tmp_path)
    )

    incident = manager.create_incident(
        source_ip="10.0.0.10",
        destination_ip="10.0.0.20",
        severity="MEDIUM",
        risk_score=30,
    )

    alert = {
        "alert_id": "NS-1002-TEST",
        "alert_type": "SYN_SCAN",
        "severity": "HIGH",
        "timestamp": "2026-09-12T01:00:01",
        "evidence": {
            "unique_ports": 25
        },
    }

    manager.add_alert(
        incident,
        alert,
        risk_score=55,
    )

    assert "NS-1002-TEST" in incident.alert_ids

    assert "SYN_SCAN" in incident.attack_types

    assert incident.risk_score == 55

    assert incident.severity == "HIGH"

    assert len(incident.timeline) >= 2


def test_severity_escalation(tmp_path):

    manager = IncidentManager(
        log_directory=str(tmp_path)
    )

    incident = manager.create_incident(
        source_ip="10.0.0.10",
        destination_ip="10.0.0.20",
        severity="LOW",
        risk_score=10,
    )

    alert = {
        "alert_id": "NS-1007-TEST",
        "alert_type": "TRAFFIC_BURST",
        "severity": "CRITICAL",
        "timestamp": "2026-09-12T01:00:05",
    }

    manager.add_alert(
        incident,
        alert,
        risk_score=90,
    )

    assert incident.severity == "CRITICAL"

    assert incident.risk_score == 90

    events = [
        event["event"]
        for event in incident.timeline
    ]

    assert "SEVERITY_ESCALATED" in events


def test_status_management(tmp_path):

    manager = IncidentManager(
        log_directory=str(tmp_path)
    )

    incident = manager.create_incident(
        source_ip="10.0.0.10",
        destination_ip="10.0.0.20",
        severity="HIGH",
        risk_score=70,
    )

    manager.update_status(
        incident.incident_id,
        "INVESTIGATING"
    )

    assert incident.status == "INVESTIGATING"

    manager.resolve_incident(
        incident.incident_id
    )

    assert incident.status == "RESOLVED"


def test_active_incidents(tmp_path):

    manager = IncidentManager(
        log_directory=str(tmp_path)
    )

    incident1 = manager.create_incident(
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        severity="HIGH",
        risk_score=60,
    )

    incident2 = manager.create_incident(
        source_ip="10.0.0.3",
        destination_ip="10.0.0.4",
        severity="MEDIUM",
        risk_score=40,
    )

    manager.resolve_incident(
        incident1.incident_id
    )

    active = manager.get_active_incidents()

    assert len(active) == 1

    assert active[0].incident_id == incident2.incident_id


def test_persistence(tmp_path):

    manager = IncidentManager(
        log_directory=str(tmp_path)
    )

    incident = manager.create_incident(
        source_ip="192.168.1.10",
        destination_ip="10.0.0.20",
        severity="CRITICAL",
        risk_score=90,
        attack_type="PORT_SCAN",
        alert_id="NS-1001",
    )

    manager2 = IncidentManager(
        log_directory=str(tmp_path)
    )

    manager2.load()

    assert len(manager2.incidents) == 1

    loaded = manager2.incidents[0]

    assert loaded.incident_id == incident.incident_id

    assert loaded.severity == "CRITICAL"

    assert loaded.risk_score == 90

    assert loaded.source_ip == "192.168.1.10"


def test_summary(tmp_path):

    manager = IncidentManager(
        log_directory=str(tmp_path)
    )

    manager.create_incident(
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        severity="CRITICAL",
        risk_score=90,
    )

    manager.create_incident(
        source_ip="10.0.0.3",
        destination_ip="10.0.0.4",
        severity="HIGH",
        risk_score=70,
    )

    summary = manager.get_summary()

    assert summary["total_incidents"] == 2

    assert summary["active_incidents"] == 2

    assert summary["severity_counts"]["CRITICAL"] == 1

    assert summary["severity_counts"]["HIGH"] == 1