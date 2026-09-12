from src.security_detector import SecurityDetector


# ========================================
# PORT SCAN
# ========================================

def test_port_scan_detection():

    detector = SecurityDetector()

    for port in range(1, 12):

        detector.inspect_packet(

            source_ip="10.0.0.5",

            destination_ip="10.0.0.10",

            source_port=50000,

            destination_port=port,

            protocol="TCP",

            direction="OUTBOUND",

            tcp_flags="SYN"
        )

    detector.detect_port_scans(
        threshold=10
    )

    assert any(
        alert.alert_type
        == "Possible Port Scan"
        for alert in detector.alerts
    )

    alert = next(
        alert
        for alert in detector.alerts
        if alert.alert_type
        == "Possible Port Scan"
    )

    assert alert.rule_id == "NET-PORT-001"

    assert alert.confidence == "HIGH"


# ========================================
# SYN SCAN
# ========================================

def test_syn_scan_detection():

    detector = SecurityDetector()

    for port in range(1, 7):

        detector.inspect_packet(

            source_ip="10.0.0.5",

            destination_ip="10.0.0.10",

            source_port=50000,

            destination_port=port,

            protocol="TCP",

            direction="OUTBOUND",

            tcp_flags="SYN"
        )

    detector.detect_syn_scans(
        threshold=5
    )

    assert any(
        alert.alert_type
        == "Possible SYN Scan"
        for alert in detector.alerts
    )


# ========================================
# HIGH ACTIVITY
# ========================================

def test_high_activity():

    detector = SecurityDetector()

    for _ in range(100):

        detector.inspect_packet(

            source_ip="10.0.0.5",

            destination_ip="10.0.0.10",

            source_port=50000,

            destination_port=443,

            protocol="TCP",

            direction="OUTBOUND",

            tcp_flags="ACK"
        )

    detector.detect_high_activity(
        threshold=100
    )

    assert any(
        alert.alert_type
        == "High Network Activity"
        for alert in detector.alerts
    )


# ========================================
# BROADCAST
# ========================================

def test_broadcast_is_ignored():

    detector = SecurityDetector()

    for port in range(1, 20):

        detector.inspect_packet(

            source_ip="10.0.0.18",

            destination_ip="255.255.255.255",

            source_port=50000,

            destination_port=port,

            protocol="UDP",

            direction="BROADCAST"
        )

    detector.detect_all()

    assert len(
        detector.alerts
    ) == 0