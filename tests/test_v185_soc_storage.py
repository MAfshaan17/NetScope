from src.soc_storage import SOCStorage
from src.incident_manager import IncidentManager
from src.profile_engine import ProfileEngine


def test_save_and_load_state(tmp_path):

    storage = SOCStorage(
        log_directory=str(tmp_path)
    )

    state = {
        "version": "1.8.5",
        "incidents": [
            {
                "incident_id": "NS-INC-0001",
                "severity": "CRITICAL",
                "risk_score": 95,
            }
        ],
        "attackers": [
            {
                "ip": "10.0.0.50",
                "risk_score": 95,
            }
        ],
        "victims": [
            {
                "ip": "10.0.0.20",
                "risk_score": 95,
            }
        ],
    }

    storage.save_state(state)

    assert storage.exists()

    loaded = storage.load_state()

    assert loaded["version"] == "1.8.5"

    assert len(loaded["incidents"]) == 1

    assert len(loaded["attackers"]) == 1

    assert len(loaded["victims"]) == 1


def test_missing_state(tmp_path):

    storage = SOCStorage(
        log_directory=str(tmp_path)
    )

    assert storage.load_state() == {}

    assert storage.exists() is False


def test_invalid_json(tmp_path):

    storage = SOCStorage(
        log_directory=str(tmp_path)
    )

    with open(
        storage.state_file,
        "w",
        encoding="utf-8",
    ) as file:

        file.write(
            "{invalid json"
        )

    assert storage.load_state() == {}


def test_save_incidents(tmp_path):

    manager = IncidentManager(
        log_directory=str(tmp_path)
    )

    incident = manager.create_incident(
        source_ip="10.0.0.50",
        destination_ip="10.0.0.20",
        severity="HIGH",
        risk_score=75,
        attack_type="PORT_SCAN",
        alert_id="NS-1001",
    )

    storage = SOCStorage(
        log_directory=str(tmp_path)
    )

    storage.save_incidents(
        manager.incidents
    )

    state = storage.load_state()

    assert len(
        state["incidents"]
    ) == 1

    assert (
        state["incidents"][0]["incident_id"]
        == incident.incident_id
    )


def test_save_profiles(tmp_path):

    profiles = ProfileEngine()

    alert = {
        "alert_id": "NS-1001",
        "rule_id": "NS-1001",
        "alert_type": "PORT_SCAN",
        "source_ip": "10.0.0.50",
        "destination_ip": "10.0.0.20",
        "severity": "HIGH",
        "timestamp": "2026-09-12T01:00:00",
        "protocol": "TCP",
        "evidence": {
            "ports": [80, 443]
        },
    }

    profiles.process_alert(
        alert,
        risk_score=80
    )

    storage = SOCStorage(
        log_directory=str(tmp_path)
    )

    storage.save_profiles(
        profiles.attackers,
        profiles.victims
    )

    state = storage.load_state()

    assert len(
        state["attackers"]
    ) == 1

    assert len(
        state["victims"]
    ) == 1

    assert (
        state["attackers"][0]["ip"]
        == "10.0.0.50"
    )

    assert (
        state["victims"][0]["ip"]
        == "10.0.0.20"
    )


def test_save_complete_soc(tmp_path):

    manager = IncidentManager(
        log_directory=str(tmp_path)
    )

    manager.create_incident(
        source_ip="10.0.0.50",
        destination_ip="10.0.0.20",
        severity="CRITICAL",
        risk_score=95,
    )

    profiles = ProfileEngine()

    profiles.process_alert(
        {
            "alert_id": "A1",
            "rule_id": "NS-1007",
            "alert_type": "TRAFFIC_BURST",
            "source_ip": "10.0.0.50",
            "destination_ip": "10.0.0.20",
            "severity": "CRITICAL",
            "timestamp": "2026-09-12T01:00:00",
        },
        risk_score=95,
    )

    storage = SOCStorage(
        log_directory=str(tmp_path)
    )

    storage.save_soc(
        manager.incidents,
        profiles.attackers,
        profiles.victims,
    )

    state = storage.load_state()

    assert state["version"] == "1.8.5"

    assert len(state["incidents"]) == 1

    assert len(state["attackers"]) == 1

    assert len(state["victims"]) == 1


def test_storage_summary(tmp_path):

    storage = SOCStorage(
        log_directory=str(tmp_path)
    )

    storage.save_state(
        {
            "version": "1.8.5",
            "incidents": [
                {"incident_id": "NS-INC-0001"}
            ],
            "attackers": [
                {"ip": "10.0.0.50"}
            ],
            "victims": [
                {"ip": "10.0.0.20"}
            ],
        }
    )

    summary = storage.get_summary()

    assert summary["version"] == "1.8.5"

    assert summary["incidents"] == 1

    assert summary["attackers"] == 1

    assert summary["victims"] == 1


def test_clear(tmp_path):

    storage = SOCStorage(
        log_directory=str(tmp_path)
    )

    storage.save_state(
        {
            "version": "1.8.5"
        }
    )

    assert storage.exists()

    storage.clear()

    assert storage.exists() is False

    assert storage.load_state() == {}