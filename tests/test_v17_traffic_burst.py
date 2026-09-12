from src.detection_engine import DetectionEngine


def test_traffic_burst_detection():

    engine = DetectionEngine(
        traffic_packet_threshold=100
    )

    alerts = []

    for _ in range(100):

        alerts.extend(
            engine.inspect_packet(
                source_ip="10.0.0.10",
                destination_ip="10.0.0.20",
                destination_port=80,
                protocol="TCP",
                size=1000,
            )
        )

    burst_alerts = [
        alert
        for alert in alerts
        if alert["rule_id"] == "NS-1007"
    ]

    assert len(burst_alerts) == 1

    assert (
        burst_alerts[0]["alert_type"]
        == "Traffic Burst"
    )


def test_normal_traffic_no_burst():

    engine = DetectionEngine(
        traffic_packet_threshold=100
    )

    alerts = []

    for _ in range(50):

        alerts.extend(
            engine.inspect_packet(
                source_ip="10.0.0.10",
                destination_ip="10.0.0.20",
                destination_port=80,
                protocol="TCP",
                size=500,
            )
        )

    burst_alerts = [
        alert
        for alert in alerts
        if alert["rule_id"] == "NS-1007"
    ]

    assert len(burst_alerts) == 0


def test_traffic_burst_byte_threshold():

    engine = DetectionEngine(
        traffic_packet_threshold=1000,
        traffic_byte_threshold=100000
    )

    alerts = []

    for _ in range(100):

        alerts.extend(
            engine.inspect_packet(
                source_ip="10.0.0.10",
                destination_ip="10.0.0.20",
                destination_port=443,
                protocol="TCP",
                size=1000,
            )
        )

    burst_alerts = [
        alert
        for alert in alerts
        if alert["rule_id"] == "NS-1007"
    ]

    assert len(burst_alerts) == 1

    evidence = burst_alerts[0]["evidence"]

    assert evidence["total_bytes"] >= 100000

    assert (
        evidence["byte_threshold_triggered"]
        is True
    )


def test_traffic_burst_duplicate_suppression():

    engine = DetectionEngine(
        traffic_packet_threshold=100
    )

    alerts = []

    for _ in range(100):

        alerts.extend(
            engine.inspect_packet(
                source_ip="10.0.0.10",
                destination_ip="10.0.0.20",
                destination_port=80,
                protocol="TCP",
                size=1000,
            )
        )

    first_count = len([
        alert
        for alert in alerts
        if alert["rule_id"] == "NS-1007"
    ])

    for _ in range(100):

        alerts.extend(
            engine.inspect_packet(
                source_ip="10.0.0.10",
                destination_ip="10.0.0.20",
                destination_port=80,
                protocol="TCP",
                size=1000,
            )
        )

    second_count = len([
        alert
        for alert in alerts
        if alert["rule_id"] == "NS-1007"
    ])

    assert first_count == 1

    assert second_count == 1

def test_traffic_burst_evidence():

    engine = DetectionEngine(
        traffic_packet_threshold=100,
        traffic_byte_threshold=1000000
    )
    alerts = []

    for _ in range(100):

        alerts.extend(
            engine.inspect_packet(
                source_ip="10.0.0.10",
                destination_ip="10.0.0.20",
                destination_port=80,
                protocol="TCP",
                size=1500,
            )
        )

    burst_alert = [
        alert
        for alert in alerts
        if alert["rule_id"] == "NS-1007"
    ][0]

    evidence = burst_alert["evidence"]

    assert evidence["packet_count"] >= 100

    assert evidence["total_bytes"] >= 150000

    assert evidence["packet_threshold"] == 100

    assert evidence["time_window_seconds"] == 5
