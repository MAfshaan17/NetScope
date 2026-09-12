from src.security_detector import SecurityDetector


def test_port_scan_detected_inside_time_window():

    detector = SecurityDetector()

    alert = None

    for port in range(1000, 1010):

        alert = detector.detect_port_scan(
            "10.0.0.1",
            "10.0.0.2",
            port,
            "TCP"
        )

    assert alert is not None

    assert alert["alert_type"] == "PORT_SCAN"

    assert alert["evidence"]["unique_ports"] == 10

    assert alert["evidence"]["time_window_seconds"] == 5


def test_syn_scan_detected_inside_time_window():

    detector = SecurityDetector()

    alert = None

    for port in range(1000, 1005):

        alert = detector.detect_syn_scan(
            "10.0.0.1",
            "10.0.0.2",
            port,
            "S"
        )

    assert alert is not None

    assert alert["alert_type"] == "SYN_SCAN"

    assert alert["evidence"]["syn_packets"] == 5


def test_normal_ack_does_not_trigger_syn_scan():

    detector = SecurityDetector()

    for port in range(1000, 1020):

        alert = detector.detect_syn_scan(
            "10.0.0.1",
            "10.0.0.2",
            port,
            "A"
        )

        assert alert is None