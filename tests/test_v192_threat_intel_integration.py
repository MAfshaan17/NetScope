from src.risk_engine import RiskEngine
from src.threat_intel import ThreatIntelEngine
from src.threat_intel_integration import ThreatIntelIntegration


def test_malicious_ti_adds_critical_risk_signal():
    ti = ThreatIntelEngine(
        malicious_ips={"198.51.100.20"}
    )
    match = ti.inspect_ip("198.51.100.20")

    risk = RiskEngine().assess_packet(
        "10.0.0.5", "198.51.100.20",
        destination_port=443,
        protocol="TCP",
        threat_intel=match,
    )

    assert risk["score"] == 30
    assert risk["severity"] == "MEDIUM"
    assert risk["signals"][0]["name"] == "THREAT_INTEL_MALICIOUS"


def test_suspicious_ti_adds_risk_without_double_counting():
    ti = ThreatIntelEngine(
        suspicious_ips={"203.0.113.50"}
    )
    match = ti.inspect_ip("203.0.113.50")

    risk = RiskEngine(
        suspicious_ips={"203.0.113.50"}
    ).assess_packet(
        "10.0.0.5", "203.0.113.50",
        threat_intel=match,
    )

    assert risk["score"] == 15
    assert [s["name"] for s in risk["signals"]] == [
        "THREAT_INTEL_SUSPICIOUS"
    ]


def test_unknown_ip_has_no_ti_signal():
    ti = ThreatIntelEngine()
    match = ti.inspect_ip("8.8.8.8")
    risk = RiskEngine().assess_packet(
        "10.0.0.5", "8.8.8.8", threat_intel=match
    )

    assert match["matched"] is False
    assert risk["score"] == 0
    assert risk["signals"] == []


def test_ti_alert_contains_evidence():
    ti = ThreatIntelEngine(
        malicious_ips={"198.51.100.20"}
    )
    integration = ThreatIntelIntegration(ti)

    alerts = integration.inspect_packet(
        "10.0.0.5", "198.51.100.20"
    )

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["rule_id"] == "NS-1008"
    assert alert["severity"] == "CRITICAL"
    assert alert["evidence"]["classification"] == "MALICIOUS"
    assert alert["evidence"]["detection_mode"] == "THREAT_INTELLIGENCE"


def test_ti_alert_duplicate_is_suppressed():
    ti = ThreatIntelEngine(
        suspicious_ips={"203.0.113.50"}
    )
    integration = ThreatIntelIntegration(ti)

    first = integration.inspect_packet(
        "10.0.0.5", "203.0.113.50"
    )
    second = integration.inspect_packet(
        "10.0.0.5", "203.0.113.50"
    )

    assert len(first) == 1
    assert second == []


def test_benign_ioc_does_not_create_security_alert():
    ti = ThreatIntelEngine(
        ioc_ips={
            "192.0.2.10": {
                "classification": "BENIGN",
                "confidence": "HIGH",
                "description": "Known benign test endpoint",
                "tags": ["allowlisted"],
            }
        }
    )
    integration = ThreatIntelIntegration(ti)

    assert integration.inspect_packet(
        "10.0.0.5", "192.0.2.10"
    ) == []
