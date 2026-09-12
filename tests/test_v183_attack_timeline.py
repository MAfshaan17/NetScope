from src.attack_timeline import AttackTimeline


def make_alert(
    alert_id,
    rule_id,
    timestamp,
    severity="HIGH",
):

    return {
        "alert_id": alert_id,
        "rule_id": rule_id,
        "alert_type": rule_id,
        "source_ip": "10.0.0.50",
        "destination_ip": "10.0.0.20",
        "severity": severity,
        "timestamp": timestamp,
        "description": f"Detected {rule_id}",
        "evidence": {
            "test": True
        },
    }


def test_add_alert():

    timeline = AttackTimeline()

    event = timeline.add_alert(
        make_alert(
            "A1",
            "NS-1001",
            "2026-09-12T01:00:00",
        )
    )

    assert event.rule_id == "NS-1001"

    assert event.event_type == "RECONNAISSANCE"

    assert event.source_ip == "10.0.0.50"

    assert timeline.event_count() == 1


def test_attack_stage_mapping():

    timeline = AttackTimeline()

    assert (
        timeline.get_attack_stage(
            {"rule_id": "NS-1001"}
        )
        == "RECONNAISSANCE"
    )

    assert (
        timeline.get_attack_stage(
            {"rule_id": "NS-1002"}
        )
        == "SCANNING"
    )

    assert (
        timeline.get_attack_stage(
            {"rule_id": "NS-1004"}
        )
        == "DISCOVERY"
    )

    assert (
        timeline.get_attack_stage(
            {"rule_id": "NS-1005"}
        )
        == "CONNECTION_FLOOD"
    )

    assert (
        timeline.get_attack_stage(
            {"rule_id": "NS-1007"}
        )
        == "TRAFFIC_FLOOD"
    )


def test_chronological_order():

    timeline = AttackTimeline()

    timeline.add_alert(
        make_alert(
            "A3",
            "NS-1007",
            "2026-09-12T01:00:10",
        )
    )

    timeline.add_alert(
        make_alert(
            "A1",
            "NS-1001",
            "2026-09-12T01:00:01",
        )
    )

    timeline.add_alert(
        make_alert(
            "A2",
            "NS-1002",
            "2026-09-12T01:00:05",
        )
    )

    events = timeline.get_events()

    assert events[0].alert_id == "A1"

    assert events[1].alert_id == "A2"

    assert events[2].alert_id == "A3"


def test_duration():

    timeline = AttackTimeline()

    timeline.add_alert(
        make_alert(
            "A1",
            "NS-1001",
            "2026-09-12T01:00:00",
        )
    )

    timeline.add_alert(
        make_alert(
            "A2",
            "NS-1002",
            "2026-09-12T01:00:10",
        )
    )

    assert timeline.get_duration_seconds() == 10.0


def test_attack_stages():

    timeline = AttackTimeline()

    timeline.add_alert(
        make_alert(
            "A1",
            "NS-1001",
            "2026-09-12T01:00:00",
        )
    )

    timeline.add_alert(
        make_alert(
            "A2",
            "NS-1002",
            "2026-09-12T01:00:05",
        )
    )

    timeline.add_alert(
        make_alert(
            "A3",
            "NS-1007",
            "2026-09-12T01:00:10",
        )
    )

    stages = timeline.get_attack_stages()

    assert stages == [
        "RECONNAISSANCE",
        "SCANNING",
        "TRAFFIC_FLOOD",
    ]


def test_first_and_last_event():

    timeline = AttackTimeline()

    timeline.add_alert(
        make_alert(
            "A1",
            "NS-1001",
            "2026-09-12T01:00:00",
        )
    )

    timeline.add_alert(
        make_alert(
            "A2",
            "NS-1002",
            "2026-09-12T01:00:05",
        )
    )

    assert (
        timeline.first_event().alert_id
        == "A1"
    )

    assert (
        timeline.last_event().alert_id
        == "A2"
    )


def test_narrative():

    timeline = AttackTimeline()

    timeline.add_alert(
        make_alert(
            "A1",
            "NS-1001",
            "2026-09-12T01:00:00",
        )
    )

    timeline.add_alert(
        make_alert(
            "A2",
            "NS-1002",
            "2026-09-12T01:00:05",
        )
    )

    narrative = timeline.generate_narrative()

    assert "10.0.0.50" in narrative

    assert "10.0.0.20" in narrative

    assert "RECONNAISSANCE" in narrative

    assert "SCANNING" in narrative


def test_summary():

    timeline = AttackTimeline()

    timeline.add_alert(
        make_alert(
            "A1",
            "NS-1001",
            "2026-09-12T01:00:00",
        )
    )

    timeline.add_alert(
        make_alert(
            "A2",
            "NS-1007",
            "2026-09-12T01:00:10",
        )
    )

    summary = timeline.get_summary()

    assert summary["event_count"] == 2

    assert summary["duration_seconds"] == 10.0

    assert (
        "RECONNAISSANCE"
        in summary["attack_stages"]
    )

    assert (
        "TRAFFIC_FLOOD"
        in summary["attack_stages"]
    )


def test_export():

    timeline = AttackTimeline()

    timeline.add_alert(
        make_alert(
            "A1",
            "NS-1001",
            "2026-09-12T01:00:00",
        )
    )

    data = timeline.to_dict()

    assert "events" in data

    assert "summary" in data

    assert len(data["events"]) == 1


def test_reset():

    timeline = AttackTimeline()

    timeline.add_alert(
        make_alert(
            "A1",
            "NS-1001",
            "2026-09-12T01:00:00",
        )
    )

    assert timeline.event_count() == 1

    timeline.reset()

    assert timeline.event_count() == 0