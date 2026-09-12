from src.attack_timeline import AttackTimeline


def make_alert(alert_id, rule_id, timestamp="2026-09-12T01:00:00",
               severity="LOW"):
    return {
        "alert_id": alert_id,
        "rule_id": rule_id,
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "severity": severity,
        "description": "test",
        "evidence": {},
        "timestamp": timestamp,
    }


def test_compatibility_api():
    timeline = AttackTimeline()
    assert timeline.get_attack_stage(
        {"rule_id": "NS-1001"}
    ) == "RECONNAISSANCE"

    timeline.add_alert(make_alert(
        "A3", "NS-1007", "2026-09-12T01:00:10"
    ))
    timeline.add_alert(make_alert(
        "A1", "NS-1001", "2026-09-12T01:00:01"
    ))
    timeline.add_alert(make_alert(
        "A2", "NS-1002", "2026-09-12T01:00:05"
    ))

    assert [e.alert_id for e in timeline.get_events()] == [
        "A1", "A2", "A3"
    ]
    assert timeline.get_duration_seconds() == 9.0
    assert timeline.first_event().alert_id == "A1"
    assert timeline.last_event().alert_id == "A3"
    assert "RECONNAISSANCE" in timeline.generate_narrative()
    assert timeline.get_summary()["event_count"] == 3
    assert len(timeline.to_dict()["events"]) == 3


def test_threat_intel_stage():
    timeline = AttackTimeline()
    event = timeline.add_alert(
        make_alert("TI-1", "NS-1008")
    )
    assert event.event_type == "THREAT_INTELLIGENCE"
