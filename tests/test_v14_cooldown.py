from datetime import datetime, timedelta

from src.security_detector import SecurityDetector


def test_duplicate_port_scan_is_suppressed():

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

    first_alert_id = alert["alert_id"]

    # Another port scan during cooldown
    alert2 = detector.detect_port_scan(
        "10.0.0.1",
        "10.0.0.2",
        1005,
        "TCP"
    )

    assert alert2 is None

    key = (
        "PORT_SCAN",
        "10.0.0.1",
        "10.0.0.2",
        "TCP"
    )

    assert detector.suppressed_alerts[key] >= 1


def test_port_scan_allowed_after_cooldown():

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

    first_alert_id = alert["alert_id"]

    key = (
        "PORT_SCAN",
        "10.0.0.1",
        "10.0.0.2",
        "TCP"
    )

    # Simulate cooldown expiration
    detector.last_alert_time[key] = (
        datetime.now()
        - detector.alert_cooldown
        - timedelta(seconds=1)
    )

    # Start a new detection burst
    detector.port_events[key].clear()

    alert2 = None

    for port in range(2000, 2005):

        alert2 = detector.detect_port_scan(
            "10.0.0.1",
            "10.0.0.2",
            port,
            "TCP"
        )

    assert alert2 is not None

    assert (
        alert2["alert_id"]
        != first_alert_id
    )


def test_syn_scan_duplicate_is_suppressed():

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

    key = (
        "SYN_SCAN",
        "10.0.0.1",
        "10.0.0.2"
    )

    alert2 = detector.detect_syn_scan(
        "10.0.0.1",
        "10.0.0.2",
        2000,
        "S"
    )

    assert alert2 is None

    assert detector.suppressed_alerts[key] >= 1


def test_syn_scan_allowed_after_cooldown():

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

    first_alert_id = alert["alert_id"]

    key = (
        "SYN_SCAN",
        "10.0.0.1",
        "10.0.0.2"
    )

    # Expire cooldown
    detector.last_alert_time[key] = (
        datetime.now()
        - detector.alert_cooldown
        - timedelta(seconds=1)
    )

    detector.syn_events[key].clear()

    alert2 = None

    for port in range(2000, 2005):

        alert2 = detector.detect_syn_scan(
            "10.0.0.1",
            "10.0.0.2",
            port,
            "S"
        )

    assert alert2 is not None

    assert (
        alert2["alert_id"]
        != first_alert_id
    )


def test_normal_ack_does_not_trigger():

    detector = SecurityDetector()

    for port in range(1000, 1020):

        alert = detector.detect_syn_scan(
            "10.0.0.1",
            "10.0.0.2",
            port,
            "A"
        )

        assert alert is None