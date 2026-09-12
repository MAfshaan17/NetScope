from src.detection_engine import DetectionEngine


def test_connection_rate_detection():

    engine = DetectionEngine(
        connection_threshold=20
    )

    alerts = []

    for port in range(20):

        alerts.extend(
            engine.inspect_packet(
                source_ip="10.0.0.10",
                destination_ip="10.0.0.20",
                destination_port=1000 + port,
                protocol="TCP",
            )
        )

    high_rate = [
        alert
        for alert in alerts
        if alert["rule_id"] == "NS-1005"
    ]

    assert len(high_rate) == 1

    assert (
        high_rate[0]["alert_type"]
        == "High Connection Rate"
    )


def test_connection_rate_below_threshold():

    engine = DetectionEngine(
        connection_threshold=20
    )

    alerts = []

    for port in range(10):

        alerts.extend(
            engine.inspect_packet(
                source_ip="10.0.0.10",
                destination_ip="10.0.0.20",
                destination_port=1000 + port,
                protocol="TCP",
            )
        )

    high_rate = [
        alert
        for alert in alerts
        if alert["rule_id"] == "NS-1005"
    ]

    assert len(high_rate) == 0


def test_connection_rate_duplicate_suppression():

    engine = DetectionEngine(
        connection_threshold=20
    )

    alerts = []

    # First burst.
    for port in range(20):

        alerts.extend(
            engine.inspect_packet(
                source_ip="10.0.0.10",
                destination_ip="10.0.0.20",
                destination_port=1000 + port,
                protocol="TCP",
            )
        )

    first_count = len([
        alert
        for alert in alerts
        if alert["rule_id"] == "NS-1005"
    ])

    # Second burst.
    for port in range(20):

        alerts.extend(
            engine.inspect_packet(
                source_ip="10.0.0.10",
                destination_ip="10.0.0.20",
                destination_port=2000 + port,
                protocol="TCP",
            )
        )

    second_count = len([
        alert
        for alert in alerts
        if alert["rule_id"] == "NS-1005"
    ])

    assert first_count == 1

    assert second_count == 1


def test_connection_rate_evidence():

    engine = DetectionEngine(
        connection_threshold=20
    )

    alerts = []

    for port in range(20):

        alerts.extend(
            engine.inspect_packet(
                source_ip="10.0.0.10",
                destination_ip="10.0.0.20",
                destination_port=1000 + port,
                protocol="TCP",
            )
        )

    alert = [
        alert
        for alert in alerts
        if alert["rule_id"] == "NS-1005"
    ][0]

    evidence = alert["evidence"]

    assert evidence["connection_count"] >= 20

    assert evidence["threshold"] == 20

    assert evidence["time_window_seconds"] == 5

    assert len(evidence["ports"]) == 20


def test_connection_rate_severity():

    engine = DetectionEngine(
        connection_threshold=20
    )

    alerts = []

    for port in range(50):

        alerts.extend(
            engine.inspect_packet(
                source_ip="10.0.0.10",
                destination_ip="10.0.0.20",
                destination_port=1000 + port,
                protocol="TCP",
            )
        )

    high_rate = [
        alert
        for alert in alerts
        if alert["rule_id"] == "NS-1005"
    ]

    assert high_rate

    assert high_rate[0]["severity"] in {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }