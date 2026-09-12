from src.security_detector import SecurityDetector


def test_high_activity_realtime():
    detector = SecurityDetector()

    alerts = []

    for _ in range(100):
        result = detector.inspect_packet(
            source_ip="10.0.0.10",
            destination_ip="10.0.0.20",
            source_port=5000,
            destination_port=80,
            protocol="TCP",
            direction="LOCAL",
            tcp_flags="ACK"
        )

        alerts.extend(result)

    high_activity = [
        alert for alert in alerts
        if alert["rule_id"] == "NS-1003"
    ]

    assert len(high_activity) >= 1
    assert high_activity[0]["alert_type"] == "HIGH_ACTIVITY"


def test_high_activity_duplicate_suppressed():
    detector = SecurityDetector()

    alerts = []

    for _ in range(100):
        alerts.extend(
            detector.inspect_packet(
                source_ip="10.0.0.10",
                destination_ip="10.0.0.20",
                source_port=5000,
                destination_port=80,
                protocol="TCP",
                direction="LOCAL",
                tcp_flags="ACK"
            )
        )

    first_count = len([
        alert for alert in alerts
        if alert["rule_id"] == "NS-1003"
    ])

    for _ in range(100):
        alerts.extend(
            detector.inspect_packet(
                source_ip="10.0.0.10",
                destination_ip="10.0.0.20",
                source_port=5000,
                destination_port=80,
                protocol="TCP",
                direction="LOCAL",
                tcp_flags="ACK"
            )
        )

    second_count = len([
        alert for alert in alerts
        if alert["rule_id"] == "NS-1003"
    ])

    assert first_count == 1
    assert second_count == 1


def test_high_activity_severity():
    detector = SecurityDetector()

    alerts = []

    for _ in range(100):
        alerts.extend(
            detector.inspect_packet(
                source_ip="10.0.0.10",
                destination_ip="10.0.0.20",
                source_port=5000,
                destination_port=80,
                protocol="TCP",
                direction="LOCAL",
                tcp_flags="ACK"
            )
        )

    high_activity = [
        alert for alert in alerts
        if alert["rule_id"] == "NS-1003"
    ]

    assert high_activity
    assert high_activity[0]["severity"] in {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    }


def test_normal_traffic_does_not_trigger_high_activity():
    detector = SecurityDetector()

    alerts = []

    for _ in range(10):
        alerts.extend(
            detector.inspect_packet(
                source_ip="10.0.0.10",
                destination_ip="10.0.0.20",
                source_port=5000,
                destination_port=80,
                protocol="TCP",
                direction="LOCAL",
                tcp_flags="ACK"
            )
        )

    high_activity = [
        alert for alert in alerts
        if alert["rule_id"] == "NS-1003"
    ]

    assert len(high_activity) == 0