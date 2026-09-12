from src.security_detector import SecurityDetector


def test_low_severity_port_scan():

    detector = SecurityDetector()

    alert = None

    for port in range(1000, 1005):

        alert = detector.detect_port_scan(
            "10.0.0.1",
            "10.0.0.2",
            port,
            "TCP"
        )

    assert alert is not None
    assert alert["alert_type"] == "PORT_SCAN"
    assert alert["severity"] == "LOW"


def test_medium_severity_port_scan():

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
    assert alert["severity"] == "MEDIUM"


def test_high_severity_port_scan():

    detector = SecurityDetector()

    alert = None

    for port in range(1000, 1020):

        alert = detector.detect_port_scan(
            "10.0.0.1",
            "10.0.0.2",
            port,
            "TCP"
        )

    assert alert is not None
    assert alert["severity"] == "HIGH"


def test_critical_port_scan():

    detector = SecurityDetector()

    alert = None

    for port in range(1000, 1050):

        alert = detector.detect_port_scan(
            "10.0.0.1",
            "10.0.0.2",
            port,
            "TCP"
        )

    assert alert is not None
    assert alert["severity"] == "CRITICAL"


def test_alert_structure():

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

    assert "alert_id" in alert
    assert "timestamp" in alert
    assert "alert_type" in alert
    assert "severity" in alert
    assert "confidence" in alert
    assert "source_ip" in alert
    assert "destination_ip" in alert
    assert "description" in alert
    assert "evidence" in alert