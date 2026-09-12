from src.incident_manager import IncidentManager
from src.correlation_engine import CorrelationEngine


def make_alert(
    alert_id,
    alert_type,
    source="10.0.0.50",
    destination="10.0.0.20",
    severity="MEDIUM",
    risk_score=30,
):

    return {
        "alert_id": alert_id,
        "alert_type": alert_type,
        "rule_id": alert_type,
        "source_ip": source,
        "destination_ip": destination,
        "severity": severity,
        "risk_score": risk_score,
        "timestamp": "2026-09-12T01:00:00",
        "evidence": {
            "test": True
        },
    }


def test_first_alert_creates_incident(tmp_path):

    manager = IncidentManager(
        log_directory=str(tmp_path)
    )

    engine = CorrelationEngine(
        incident_manager=manager
    )

    alert = make_alert(
        "NS-1001-TEST",
        "PORT_SCAN",
        severity="HIGH",
        risk_score=60,
    )

    incident = engine.process_alert(
        alert
    )

    assert incident is not None

    assert incident.incident_id == "NS-INC-0001"

    assert incident.source_ip == "10.0.0.50"

    assert incident.destination_ip == "10.0.0.20"

    assert incident.risk_score == 60

    assert "PORT_SCAN" in incident.attack_types


def test_related_alerts_are_correlated(tmp_path):

    manager = IncidentManager(
        log_directory=str(tmp_path)
    )

    engine = CorrelationEngine(
        incident_manager=manager
    )

    alert1 = make_alert(
        "NS-1001-TEST",
        "PORT_SCAN",
        severity="MEDIUM",
        risk_score=40,
    )

    alert2 = make_alert(
        "NS-1002-TEST",
        "SYN_SCAN",
        severity="HIGH",
        risk_score=70,
    )

    incident1 = engine.process_alert(
        alert1
    )

    incident2 = engine.process_alert(
        alert2
    )

    assert incident1.incident_id == incident2.incident_id

    assert len(manager.incidents) == 1

    assert "PORT_SCAN" in incident2.attack_types

    assert "SYN_SCAN" in incident2.attack_types

    assert "NS-1001-TEST" in incident2.alert_ids

    assert "NS-1002-TEST" in incident2.alert_ids


def test_attack_chain_created(tmp_path):

    manager = IncidentManager(
        log_directory=str(tmp_path)
    )

    engine = CorrelationEngine(
        incident_manager=manager
    )

    engine.process_alert(
        make_alert(
            "NS-1001",
            "PORT_SCAN",
        )
    )

    engine.process_alert(
        make_alert(
            "NS-1002",
            "SYN_SCAN",
        )
    )

    chain = engine.get_attack_chain(
        "10.0.0.50",
        "10.0.0.20",
    )

    assert chain is not None

    assert len(chain.alert_ids) == 2

    assert len(chain.attack_types) == 2

    assert chain.incident_id == "NS-INC-0001"


def test_severity_escalates(tmp_path):

    manager = IncidentManager(
        log_directory=str(tmp_path)
    )

    engine = CorrelationEngine(
        incident_manager=manager
    )

    engine.process_alert(
        make_alert(
            "NS-1001",
            "PORT_SCAN",
            severity="LOW",
            risk_score=20,
        )
    )

    incident = engine.process_alert(
        make_alert(
            "NS-1007",
            "TRAFFIC_BURST",
            severity="CRITICAL",
            risk_score=95,
        )
    )

    assert incident.severity == "CRITICAL"

    assert incident.risk_score == 95


def test_different_attackers_create_different_incidents(tmp_path):

    manager = IncidentManager(
        log_directory=str(tmp_path)
    )

    engine = CorrelationEngine(
        incident_manager=manager
    )

    incident1 = engine.process_alert(
        make_alert(
            "NS-1001-A",
            "PORT_SCAN",
            source="10.0.0.50",
        )
    )

    incident2 = engine.process_alert(
        make_alert(
            "NS-1001-B",
            "PORT_SCAN",
            source="10.0.0.60",
        )
    )

    assert incident1.incident_id != incident2.incident_id

    assert len(manager.incidents) == 2


def test_different_targets_create_different_incidents(tmp_path):

    manager = IncidentManager(
        log_directory=str(tmp_path)
    )

    engine = CorrelationEngine(
        incident_manager=manager
    )

    incident1 = engine.process_alert(
        make_alert(
            "NS-1001-A",
            "PORT_SCAN",
            destination="10.0.0.20",
        )
    )

    incident2 = engine.process_alert(
        make_alert(
            "NS-1001-B",
            "PORT_SCAN",
            destination="10.0.0.30",
        )
    )

    assert incident1.incident_id != incident2.incident_id

    assert len(manager.incidents) == 2


def test_duplicate_alert_not_added_twice(tmp_path):

    manager = IncidentManager(
        log_directory=str(tmp_path)
    )

    engine = CorrelationEngine(
        incident_manager=manager
    )

    alert = make_alert(
        "NS-1001-DUP",
        "PORT_SCAN",
    )

    incident1 = engine.process_alert(
        alert
    )

    incident2 = engine.process_alert(
        alert
    )

    assert incident1.incident_id == incident2.incident_id

    assert len(manager.incidents) == 1

    assert incident2.alert_ids.count(
        "NS-1001-DUP"
    ) == 1


def test_multiple_attack_types_same_chain(tmp_path):

    manager = IncidentManager(
        log_directory=str(tmp_path)
    )

    engine = CorrelationEngine(
        incident_manager=manager
    )

    attack_types = [
        "PORT_SCAN",
        "SYN_SCAN",
        "DNS_BURST",
        "HIGH_CONNECTION_RATE",
        "TRAFFIC_BURST",
    ]

    for index, attack_type in enumerate(
        attack_types
    ):

        engine.process_alert(
            make_alert(
                f"NS-{index}",
                attack_type,
                severity="HIGH",
                risk_score=60 + index,
            )
        )

    assert len(manager.incidents) == 1

    incident = manager.incidents[0]

    assert len(
        incident.attack_types
    ) == 5

    assert len(
        incident.alert_ids
    ) == 5

    assert incident.severity == "HIGH"

    assert incident.risk_score == 64