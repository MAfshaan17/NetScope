from src.detection_engine import DetectionEngine


def test_dns_anomaly_detection():

    engine = DetectionEngine(
        dns_threshold=20
    )

    alerts = []

    for i in range(20):

        alerts.extend(
            engine.inspect_packet(
                source_ip="10.0.0.10",
                destination_ip="8.8.8.8",
                destination_port=53,
                protocol="UDP",
                query_name=f"example{i}.com",
            )
        )

    dns_alerts = [
        alert
        for alert in alerts
        if alert["rule_id"] == "NS-1004"
    ]

    assert len(dns_alerts) == 1

    assert (
        dns_alerts[0]["alert_type"]
        == "DNS Request Burst"
    )


def test_normal_dns_traffic():

    engine = DetectionEngine(
        dns_threshold=20
    )

    alerts = []

    for i in range(10):

        alerts.extend(
            engine.inspect_packet(
                source_ip="10.0.0.10",
                destination_ip="8.8.8.8",
                destination_port=53,
                protocol="UDP",
                query_name=f"example{i}.com",
            )
        )

    dns_alerts = [
        alert
        for alert in alerts
        if alert["rule_id"] == "NS-1004"
    ]

    assert len(dns_alerts) == 0


def test_dns_duplicate_suppression():

    engine = DetectionEngine(
        dns_threshold=20
    )

    alerts = []

    for i in range(20):

        alerts.extend(
            engine.inspect_packet(
                source_ip="10.0.0.10",
                destination_ip="8.8.8.8",
                destination_port=53,
                protocol="UDP",
                query_name=f"first{i}.com",
            )
        )

    first_count = len([
        alert
        for alert in alerts
        if alert["rule_id"] == "NS-1004"
    ])

    for i in range(20):

        alerts.extend(
            engine.inspect_packet(
                source_ip="10.0.0.10",
                destination_ip="8.8.8.8",
                destination_port=53,
                protocol="UDP",
                query_name=f"second{i}.com",
            )
        )

    second_count = len([
        alert
        for alert in alerts
        if alert["rule_id"] == "NS-1004"
    ])

    assert first_count == 1

    assert second_count == 1


def test_dns_evidence():

    engine = DetectionEngine(
        dns_threshold=20
    )

    alerts = []

    for i in range(20):

        alerts.extend(
            engine.inspect_packet(
                source_ip="10.0.0.10",
                destination_ip="8.8.8.8",
                destination_port=53,
                protocol="UDP",
                query_name=f"example{i}.com",
            )
        )

    dns_alert = [
        alert
        for alert in alerts
        if alert["rule_id"] == "NS-1004"
    ][0]

    evidence = dns_alert["evidence"]

    assert (
        evidence["dns_request_count"]
        >= 20
    )

    assert (
        evidence["threshold"]
        == 20
    )

    assert (
        evidence["time_window_seconds"]
        == 5
    )

    assert (
        evidence["unique_queries"]
        == 20
    )


def test_non_dns_udp_is_not_dns_anomaly():

    engine = DetectionEngine(
        dns_threshold=20
    )

    alerts = []

    for i in range(25):

        alerts.extend(
            engine.inspect_packet(
                source_ip="10.0.0.10",
                destination_ip="8.8.8.8",
                destination_port=443,
                protocol="UDP",
            )
        )

    dns_alerts = [
        alert
        for alert in alerts
        if alert["rule_id"] == "NS-1004"
    ]

    assert len(dns_alerts) == 0