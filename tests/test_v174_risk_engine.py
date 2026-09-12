from src.risk_engine import RiskEngine


def test_risk_engine_normal_packet():

    engine = RiskEngine()

    result = engine.assess_packet(
        source_ip="10.0.0.10",
        destination_ip="1.1.1.1",
        destination_port=443,
        protocol="TCP",
    )

    assert result["rule_id"] == "NS-1006"
    assert result["score"] == 0
    assert result["severity"] == "LOW"


def test_risk_engine_suspicious_destination():

    engine = RiskEngine(
        suspicious_ips={
            "203.0.113.50"
        }
    )

    result = engine.assess_packet(
        source_ip="10.0.0.10",
        destination_ip="203.0.113.50",
        destination_port=443,
        protocol="TCP",
    )

    assert result["score"] == 25
    assert result["severity"] == "MEDIUM"


def test_risk_engine_unusual_port():

    engine = RiskEngine()

    result = engine.assess_packet(
        source_ip="10.0.0.10",
        destination_ip="10.0.0.20",
        destination_port=3389,
        protocol="TCP",
    )

    assert result["score"] == 10

    assert any(
        signal["name"] == "UNUSUAL_PORT"
        for signal in result["signals"]
    )


def test_risk_engine_combines_alerts():

    engine = RiskEngine(
        suspicious_ips={
            "203.0.113.50"
        }
    )

    alerts = [
        {
            "rule_id": "NS-1001",
            "description": "Port scan detected",
        },
        {
            "rule_id": "NS-1004",
            "description": "DNS burst detected",
        },
        {
            "rule_id": "NS-1007",
            "description": "Traffic burst detected",
        },
    ]

    result = engine.assess_packet(
        source_ip="10.0.0.10",
        destination_ip="203.0.113.50",
        destination_port=3389,
        protocol="TCP",
        alerts=alerts,
    )

    assert result["score"] == 90
    assert result["severity"] == "CRITICAL"
    assert result["confidence"] == "HIGH"


def test_risk_engine_summary():

    engine = RiskEngine(
        suspicious_ips={
            "203.0.113.50"
        }
    )

    engine.assess_packet(
        source_ip="10.0.0.10",
        destination_ip="203.0.113.50",
        destination_port=3389,
        protocol="TCP",
    )

    summary = engine.get_summary()

    assert summary["total_assessments"] == 1
    assert summary["highest_score"] == 35
    assert summary["highest_severity"] == "MEDIUM"