"""
NetScope Attack Timeline
V1.9.2
Compatibility-preserving implementation with Threat Intelligence support.
"""

from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any


# ============================================================
# TIMELINE EVENT
# ============================================================

@dataclass
class TimelineEvent:
    timestamp: str
    event_type: str
    rule_id: str
    alert_id: str
    source_ip: str
    destination_ip: str
    severity: str
    description: str
    evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ============================================================
# ATTACK TIMELINE
# ============================================================

class AttackTimeline:

    # --------------------------------------------------------
    # Attack stage mapping
    # --------------------------------------------------------

    ATTACK_STAGES = {
        # Port scanning
        "NS-1001": "RECONNAISSANCE",
        "PORT_SCAN": "RECONNAISSANCE",

        # SYN scanning
        "NS-1002": "SCANNING",
        "SYN_SCAN": "SCANNING",

        # DNS burst
        "NS-1004": "DISCOVERY",
        "DNS_BURST": "DISCOVERY",

        # Connection flooding
        "NS-1005": "CONNECTION_FLOOD",
        "HIGH_CONNECTION_RATE": "CONNECTION_FLOOD",

        # Traffic flooding
        "NS-1007": "TRAFFIC_FLOOD",
        "TRAFFIC_BURST": "TRAFFIC_FLOOD",

        # High activity
        "NS-1003": "HIGH_ACTIVITY",
        "HIGH_ACTIVITY": "HIGH_ACTIVITY",

        # Threat intelligence
        "NS-1008": "THREAT_INTELLIGENCE",
        "THREAT_INTELLIGENCE": "THREAT_INTELLIGENCE",
    }

    # --------------------------------------------------------
    # Constructor
    # --------------------------------------------------------

    def __init__(self):
        self.events: list[TimelineEvent] = []

    # --------------------------------------------------------
    # Timestamp helper
    # --------------------------------------------------------

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime:
        """
        Convert an ISO timestamp into datetime.

        Invalid timestamps are placed at the beginning so that
        sorting never crashes.
        """

        try:
            return datetime.fromisoformat(str(value))
        except (TypeError, ValueError):
            return datetime.min

    # --------------------------------------------------------
    # Attack stage lookup
    # --------------------------------------------------------

    @classmethod
    def get_attack_stage(
        cls,
        alert: dict[str, Any]
    ) -> str:

        rule_id = alert.get("rule_id", "")
        attack_type = alert.get("attack_type", "")
        alert_type = alert.get("alert_type", "")

        # Rule ID has highest priority.
        if rule_id in cls.ATTACK_STAGES:
            return cls.ATTACK_STAGES[rule_id]

        # Then attack type.
        if attack_type in cls.ATTACK_STAGES:
            return cls.ATTACK_STAGES[attack_type]

        # Finally alert type.
        if alert_type in cls.ATTACK_STAGES:
            return cls.ATTACK_STAGES[alert_type]

        return "UNKNOWN"

    # --------------------------------------------------------
    # Add single alert
    # --------------------------------------------------------

    def add_alert(
        self,
        alert: dict[str, Any]
    ) -> TimelineEvent:

        event = TimelineEvent(
            timestamp=alert.get(
                "timestamp",
                datetime.now().isoformat()
            ),

            event_type=self.get_attack_stage(alert),

            rule_id=alert.get(
                "rule_id",
                "UNKNOWN"
            ),

            alert_id=alert.get(
                "alert_id",
                "UNKNOWN"
            ),

            source_ip=alert.get(
                "source_ip",
                "UNKNOWN"
            ),

            destination_ip=alert.get(
                "destination_ip",
                "UNKNOWN"
            ),

            severity=alert.get(
                "severity",
                "LOW"
            ),

            description=alert.get(
                "description",
                ""
            ),

            evidence=alert.get(
                "evidence",
                {}
            ),
        )

        self.events.append(event)

        # IMPORTANT:
        # Keep the internal event list chronological.
        self.events.sort(
            key=lambda event: self._parse_timestamp(
                event.timestamp
            )
        )

        return event

    # --------------------------------------------------------
    # Add multiple alerts
    # --------------------------------------------------------

    def add_alerts(
        self,
        alerts: list[dict[str, Any]]
    ) -> list[TimelineEvent]:

        events = []

        for alert in alerts:
            events.append(
                self.add_alert(alert)
            )

        return events

    # --------------------------------------------------------
    # Restore timeline from persisted incident
    # --------------------------------------------------------

    def load_incident(
        self,
        incident: Any
    ) -> list[TimelineEvent]:

        if isinstance(incident, dict):
            data = incident
        else:
            data = incident.to_dict()

        incident_timeline = data.get(
            "timeline",
            []
        )

        for item in incident_timeline:

            # IncidentManager stores correlation events.
            if item.get("event") != "ALERT_CORRELATED":
                continue

            alert = {
                "timestamp": item.get(
                    "timestamp",
                    datetime.now().isoformat()
                ),

                "rule_id": item.get(
                    "rule_id",
                    "UNKNOWN"
                ),

                "alert_id": item.get(
                    "alert_id",
                    "UNKNOWN"
                ),

                "source_ip": data.get(
                    "source_ip",
                    "UNKNOWN"
                ),

                "destination_ip": data.get(
                    "destination_ip",
                    "UNKNOWN"
                ),

                "severity": item.get(
                    "severity",
                    data.get(
                        "severity",
                        "LOW"
                    )
                ),

                "description": item.get(
                    "description",
                    ""
                ),

                "evidence": item.get(
                    "evidence",
                    {}
                ),

                "attack_type": item.get(
                    "attack_type",
                    ""
                ),

                "alert_type": item.get(
                    "alert_type",
                    ""
                ),
            }

            self.add_alert(alert)

        return self.get_events()

    # --------------------------------------------------------
    # Get events
    # --------------------------------------------------------

    def get_events(self) -> list[TimelineEvent]:

        # Always return chronological order.
        return sorted(
            self.events,
            key=lambda event: self._parse_timestamp(
                event.timestamp
            )
        )

    # --------------------------------------------------------
    # Get attack stages
    # --------------------------------------------------------

    def get_attack_stages(self) -> list[str]:

        return [
            event.event_type
            for event in self.get_events()
        ]

    # --------------------------------------------------------
    # Duration
    # --------------------------------------------------------

    def duration(self) -> float:

        events = self.get_events()

        if len(events) < 2:
            return 0.0

        first = self._parse_timestamp(
            events[0].timestamp
        )

        last = self._parse_timestamp(
            events[-1].timestamp
        )

        return (
            last - first
        ).total_seconds()

    # Compatibility alias
    def get_duration_seconds(self) -> float:
        return self.duration()

    # --------------------------------------------------------
    # First / Last
    # --------------------------------------------------------

    def first_event(
        self
    ) -> TimelineEvent | None:

        events = self.get_events()

        if not events:
            return None

        return events[0]

    def last_event(
        self
    ) -> TimelineEvent | None:

        events = self.get_events()

        if not events:
            return None

        return events[-1]

    def first_seen(self) -> str | None:

        event = self.first_event()

        if event is None:
            return None

        return event.timestamp

    def last_seen(self) -> str | None:

        event = self.last_event()

        if event is None:
            return None

        return event.timestamp

    # --------------------------------------------------------
    # Event count
    # --------------------------------------------------------

    def event_count(self) -> int:
        return len(self.events)

    # --------------------------------------------------------
    # Narrative
    # --------------------------------------------------------

    def narrative(self) -> str:

        events = self.get_events()

        if not events:
            return "No attack timeline events."

        first = events[0]

        source_ip = first.source_ip
        destination_ip = first.destination_ip

        stages = " -> ".join(
            event.event_type
            for event in events
        )

        # Include attacker and victim IPs so the narrative
        # is useful in the SOC dashboard and tests.
        return (
            f"Attack timeline for {source_ip} "
            f"against {destination_ip}: "
            f"{stages}"
        )

    # Compatibility alias
    def generate_narrative(self) -> str:
        return self.narrative()

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    def summary(self) -> dict[str, Any]:

        return {
            "event_count": self.event_count(),

            "first_seen": self.first_seen(),

            "last_seen": self.last_seen(),

            "duration_seconds": self.duration(),

            "attack_stages": self.get_attack_stages(),

            "narrative": self.narrative(),
        }

    # Compatibility alias
    def get_summary(self) -> dict[str, Any]:
        return self.summary()

    # --------------------------------------------------------
    # Export events
    # --------------------------------------------------------

    def export(self) -> list[dict[str, Any]]:

        return [
            event.to_dict()
            for event in self.get_events()
        ]

    # --------------------------------------------------------
    # Export complete timeline
    # --------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:

        summary = self.summary()

        return {
            "summary": summary,
            "events": self.export(),
        }

    # --------------------------------------------------------
    # Reset
    # --------------------------------------------------------

    def reset(self) -> None:
        self.events.clear()