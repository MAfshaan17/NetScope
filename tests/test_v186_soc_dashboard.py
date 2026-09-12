from src.dashboard import NetworkDashboard


def test_dashboard_packet():

    dashboard = NetworkDashboard()

    dashboard.update_packet(
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        protocol="TCP",
        size=100,
    )

    assert dashboard.packet_count == 1

    assert dashboard.total_bytes == 100

    assert dashboard.protocol_counts["TCP"] == 1


def test_dashboard_alert():

    dashboard = NetworkDashboard()

    dashboard.update_alert(
        {
            "alert_id": "A1",
            "rule_id": "NS-1001",
            "source_ip": "10.0.0.50",
            "destination_ip": "10.0.0.20",
            "severity": "HIGH",
        }
    )

    assert dashboard.alert_count == 1

    assert (
        dashboard.severity_counts["HIGH"]
        == 1
    )

    assert (
        dashboard.rule_counts["NS-1001"]
        == 1
    )


def test_dashboard_risk():

    dashboard = NetworkDashboard()

    dashboard.update_risk(
        {
            "score": 85
        }
    )

    assert dashboard.risk_score == 85


def test_dashboard_incident():

    dashboard = NetworkDashboard()

    incident = {
        "incident_id": "NS-INC-0001",
        "source_ip": "10.0.0.50",
        "destination_ip": "10.0.0.20",
        "severity": "CRITICAL",
        "risk_score": 95,
        "status": "OPEN",
    }

    dashboard.update_incident(
        incident
    )

    assert len(
        dashboard.recent_incidents
    ) == 1

    assert dashboard.risk_score == 95


def test_incident_summary():

    dashboard = NetworkDashboard()

    dashboard.update_incident_summary(
        {
            "total_incidents": 5,
            "active_incidents": 3,
            "severity_counts": {
                "CRITICAL": 1,
                "HIGH": 1,
                "MEDIUM": 2,
                "LOW": 1,
            },
        }
    )

    assert dashboard.incident_count == 5

    assert dashboard.active_incidents == 3

    assert dashboard.critical_incidents == 1

    assert dashboard.high_incidents == 1


def test_profiles():

    dashboard = NetworkDashboard()

    attackers = [
        {
            "ip": "10.0.0.50",
            "risk_score": 90,
            "severity": "CRITICAL",
            "alert_count": 10,
        }
    ]

    victims = [
        {
            "ip": "10.0.0.20",
            "risk_score": 80,
            "severity": "HIGH",
            "attack_count": 5,
        }
    ]

    dashboard.update_profiles(
        attackers,
        victims,
    )

    assert len(
        dashboard.attackers
    ) == 1

    assert len(
        dashboard.victims
    ) == 1


def test_timeline():

    dashboard = NetworkDashboard()

    dashboard.update_timeline(
        [
            {
                "timestamp":
                    "2026-09-12T01:00:00",
                "event":
                    "ALERT_CORRELATED",
                "alert_type":
                    "PORT_SCAN",
            }
        ]
    )

    assert len(
        dashboard.timeline_events
    ) == 1


def test_dashboard_render():

    dashboard = NetworkDashboard()

    dashboard.update_packet(
        "10.0.0.1",
        "10.0.0.2",
        "TCP",
        100,
    )

    dashboard.update_alert(
        {
            "rule_id": "NS-1001",
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "severity": "HIGH",
        }
    )

    output = dashboard.render()

    assert output is not None


def test_dashboard_live():

    dashboard = NetworkDashboard()

    with dashboard.live(
        refresh_per_second=10
    ):

        dashboard.update_packet(
            "10.0.0.1",
            "10.0.0.2",
            "TCP",
            100,
        )

        dashboard.refresh()

    assert dashboard.packet_count == 1