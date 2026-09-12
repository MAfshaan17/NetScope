from src.profile_engine import ProfileEngine


def make_alert(
    alert_type,
    source="10.0.0.50",
    destination="10.0.0.20",
    severity="HIGH",
    risk_score=70,
    destination_port=80,
):

    return {
        "alert_id": f"TEST-{alert_type}",
        "rule_id": alert_type,
        "alert_type": alert_type,
        "source_ip": source,
        "destination_ip": destination,
        "severity": severity,
        "risk_score": risk_score,
        "timestamp": "2026-09-12T01:00:00",
        "destination_port": destination_port,
        "protocol": "TCP",
        "evidence": {
            "ports": [80, 443, 8080],
        },
    }


def test_attacker_profile():

    engine = ProfileEngine()

    engine.process_alert(
        make_alert(
            "NS-1001"
        ),
        risk_score=75,
    )

    attacker = engine.get_attacker(
        "10.0.0.50"
    )

    assert attacker.ip == "10.0.0.50"

    assert attacker.alert_count == 1

    assert attacker.port_scan_count == 1

    assert attacker.risk_score == 75

    assert attacker.severity == "HIGH"

    assert "10.0.0.20" in attacker.targets


def test_victim_profile():

    engine = ProfileEngine()

    engine.process_alert(
        make_alert(
            "NS-1002"
        ),
        risk_score=80,
    )

    victim = engine.get_victim(
        "10.0.0.20"
    )

    assert victim.ip == "10.0.0.20"

    assert victim.attack_count == 1

    assert victim.risk_score == 80

    assert victim.severity == "HIGH"

    assert "10.0.0.50" in victim.sources


def test_multiple_attack_types():

    engine = ProfileEngine()

    attack_types = [
        "NS-1001",
        "NS-1002",
        "NS-1004",
        "NS-1005",
        "NS-1007",
    ]

    for index, attack_type in enumerate(
        attack_types
    ):

        engine.process_alert(
            make_alert(
                attack_type,
            ),
            risk_score=50 + index,
        )

    attacker = engine.get_attacker(
        "10.0.0.50"
    )

    assert attacker.alert_count == 5

    assert attacker.port_scan_count == 1

    assert attacker.syn_scan_count == 1

    assert attacker.dns_burst_count == 1

    assert attacker.connection_rate_count == 1

    assert attacker.traffic_burst_count == 1


def test_multiple_targets():

    engine = ProfileEngine()

    engine.process_alert(
        make_alert(
            "NS-1001",
            destination="10.0.0.20",
        )
    )

    engine.process_alert(
        make_alert(
            "NS-1002",
            destination="10.0.0.30",
        )
    )

    attacker = engine.get_attacker(
        "10.0.0.50"
    )

    assert len(attacker.targets) == 2

    assert "10.0.0.20" in attacker.targets

    assert "10.0.0.30" in attacker.targets


def test_multiple_attackers():

    engine = ProfileEngine()

    engine.process_alert(
        make_alert(
            "NS-1001",
            source="10.0.0.50",
        )
    )

    engine.process_alert(
        make_alert(
            "NS-1002",
            source="10.0.0.60",
        )
    )

    assert len(engine.attackers) == 2

    assert (
        "10.0.0.50"
        in engine.attackers
    )

    assert (
        "10.0.0.60"
        in engine.attackers
    )


def test_ports_and_protocols():

    engine = ProfileEngine()

    engine.process_alert(
        make_alert(
            "NS-1001"
        )
    )

    attacker = engine.get_attacker(
        "10.0.0.50"
    )

    victim = engine.get_victim(
        "10.0.0.20"
    )

    assert 80 in attacker.ports

    assert 443 in attacker.ports

    assert "TCP" in attacker.protocols

    assert 80 in victim.targeted_ports

    assert 443 in victim.targeted_ports

    assert "TCP" in victim.protocols


def test_risk_escalation():

    engine = ProfileEngine()

    engine.process_alert(
        make_alert(
            "NS-1001",
            severity="LOW",
        ),
        risk_score=20,
    )

    engine.process_alert(
        make_alert(
            "NS-1007",
            severity="CRITICAL",
        ),
        risk_score=95,
    )

    attacker = engine.get_attacker(
        "10.0.0.50"
    )

    victim = engine.get_victim(
        "10.0.0.20"
    )

    assert attacker.risk_score == 95

    assert attacker.severity == "CRITICAL"

    assert victim.risk_score == 95

    assert victim.severity == "CRITICAL"


def test_incident_profile():

    engine = ProfileEngine()

    class FakeIncident:

        source_ip = "10.0.0.50"

        destination_ip = "10.0.0.20"

        risk_score = 90

        severity = "CRITICAL"

        last_seen = "2026-09-12T01:01:00"

    engine.process_incident(
        FakeIncident()
    )

    attacker = engine.get_attacker(
        "10.0.0.50"
    )

    victim = engine.get_victim(
        "10.0.0.20"
    )

    assert attacker.incident_count == 1

    assert attacker.risk_score == 90

    assert victim.incident_count == 1

    assert victim.risk_score == 90


def test_top_attackers():

    engine = ProfileEngine()

    engine.process_alert(
        make_alert(
            "NS-1001",
            source="10.0.0.50",
        ),
        risk_score=90,
    )

    engine.process_alert(
        make_alert(
            "NS-1002",
            source="10.0.0.60",
        ),
        risk_score=50,
    )

    top = engine.top_attackers(
        limit=1
    )

    assert len(top) == 1

    assert top[0].ip == "10.0.0.50"


def test_summary_and_reset():

    engine = ProfileEngine()

    engine.process_alert(
        make_alert(
            "NS-1001"
        ),
        risk_score=70,
    )

    summary = engine.get_summary()

    assert summary["attacker_count"] == 1

    assert summary["victim_count"] == 1

    engine.reset()

    assert len(engine.attackers) == 0

    assert len(engine.victims) == 0