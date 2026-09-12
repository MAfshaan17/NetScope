"""
NetScope V1.8.2
Alert Correlation Engine

Correlates related security alerts into incidents.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from .incident_manager import IncidentManager, Incident


@dataclass
class CorrelationEvent:
    timestamp: datetime
    alert: Dict[str, Any]


@dataclass
class AttackChain:
    source_ip: str
    destination_ip: str

    alert_ids: List[str] = field(default_factory=list)
    attack_types: List[str] = field(default_factory=list)

    first_seen: str = ""
    last_seen: str = ""

    risk_score: int = 0
    severity: str = "LOW"

    incident_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "alert_ids": self.alert_ids,
            "attack_types": self.attack_types,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "incident_id": self.incident_id,
        }


class CorrelationEngine:

    def __init__(
        self,
        incident_manager: IncidentManager,
        correlation_window_seconds: int = 60,
    ):

        self.incident_manager = incident_manager

        self.correlation_window = timedelta(
            seconds=correlation_window_seconds
        )

        self.events: Dict[
            tuple[str, str],
            List[CorrelationEvent]
        ] = {}

        self.chains: Dict[
            tuple[str, str],
            AttackChain
        ] = {}

    # ---------------------------------------------------------
    # TIME
    # ---------------------------------------------------------

    @staticmethod
    def _now() -> datetime:
        return datetime.now()

    @staticmethod
    def _timestamp() -> str:
        return datetime.now().isoformat(
            timespec="seconds"
        )

    # ---------------------------------------------------------
    # SEVERITY
    # ---------------------------------------------------------

    @staticmethod
    def severity_rank(severity: str) -> int:

        return {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }.get(
            str(severity).upper(),
            1
        )

    @classmethod
    def highest_severity(
        cls,
        current: str,
        new: str,
    ) -> str:

        if cls.severity_rank(new) > cls.severity_rank(current):
            return str(new).upper()

        return str(current).upper()

    # ---------------------------------------------------------
    # EXTRACT ALERT DATA
    # ---------------------------------------------------------

    @staticmethod
    def _get_source_ip(
        alert: Dict[str, Any]
    ) -> str:

        return str(
            alert.get(
                "source_ip",
                "UNKNOWN"
            )
        )

    @staticmethod
    def _get_destination_ip(
        alert: Dict[str, Any]
    ) -> str:

        return str(
            alert.get(
                "destination_ip",
                "UNKNOWN"
            )
        )

    @staticmethod
    def _get_alert_type(
        alert: Dict[str, Any]
    ) -> str:

        return str(
            alert.get(
                "alert_type",
                alert.get(
                    "rule_id",
                    "UNKNOWN"
                )
            )
        )

    @staticmethod
    def _get_alert_id(
        alert: Dict[str, Any]
    ) -> Optional[str]:

        value = alert.get("alert_id")

        if value is None:
            return None

        return str(value)

    @staticmethod
    def _get_risk_score(
        alert: Dict[str, Any]
    ) -> int:

        value = alert.get(
            "risk_score",
            alert.get(
                "score",
                0
            )
        )

        try:
            return int(value)
        except (
            TypeError,
            ValueError,
        ):
            return 0

    # ---------------------------------------------------------
    # CLEAN OLD EVENTS
    # ---------------------------------------------------------

    def _cleanup_events(
        self,
        key: tuple[str, str],
        now: datetime,
    ) -> None:

        if key not in self.events:
            return

        cutoff = now - self.correlation_window

        self.events[key] = [
            event
            for event in self.events[key]
            if event.timestamp >= cutoff
        ]

    # ---------------------------------------------------------
    # GET / CREATE CHAIN
    # ---------------------------------------------------------

    def _get_or_create_chain(
        self,
        source_ip: str,
        destination_ip: str,
    ) -> AttackChain:

        key = (
            source_ip,
            destination_ip
        )

        if key not in self.chains:

            self.chains[key] = AttackChain(
                source_ip=source_ip,
                destination_ip=destination_ip,
            )

        return self.chains[key]

    # ---------------------------------------------------------
    # PROCESS ALERT
    # ---------------------------------------------------------

    def process_alert(
        self,
        alert: Dict[str, Any],
        risk_score: Optional[int] = None,
    ) -> Optional[Incident]:

        source_ip = self._get_source_ip(alert)

        destination_ip = self._get_destination_ip(alert)

        alert_type = self._get_alert_type(alert)

        alert_id = self._get_alert_id(alert)

        severity = str(
            alert.get(
                "severity",
                "LOW"
            )
        ).upper()

        timestamp_text = alert.get(
            "timestamp"
        )

        now = self._now()

        if timestamp_text:

            try:
                event_time = datetime.fromisoformat(
                    str(timestamp_text)
                )
            except ValueError:
                event_time = now

        else:
            event_time = now

        key = (
            source_ip,
            destination_ip
        )

        # -----------------------------------------------------
        # STORE EVENT
        # -----------------------------------------------------

        self.events.setdefault(
            key,
            []
        ).append(
            CorrelationEvent(
                timestamp=event_time,
                alert=alert,
            )
        )

        self._cleanup_events(
            key,
            event_time
        )

        # -----------------------------------------------------
        # GET ATTACK CHAIN
        # -----------------------------------------------------

        chain = self._get_or_create_chain(
            source_ip,
            destination_ip
        )

        # -----------------------------------------------------
        # DUPLICATE ALERT PROTECTION
        # -----------------------------------------------------

        if (
            alert_id
            and
            alert_id in chain.alert_ids
        ):

            incident = None

            if chain.incident_id:
                incident = (
                    self.incident_manager.get_incident(
                        chain.incident_id
                    )
                )

            return incident

        # -----------------------------------------------------
        # ADD ALERT
        # -----------------------------------------------------

        if alert_id:
            chain.alert_ids.append(
                alert_id
            )

        if alert_type not in chain.attack_types:

            chain.attack_types.append(
                alert_type
            )

        if not chain.first_seen:

            chain.first_seen = (
                event_time.isoformat(
                    timespec="seconds"
                )
            )

        chain.last_seen = (
            event_time.isoformat(
                timespec="seconds"
            )
        )

        # -----------------------------------------------------
        # RISK
        # -----------------------------------------------------

        alert_risk = (
            risk_score
            if risk_score is not None
            else self._get_risk_score(alert)
        )

        chain.risk_score = max(
            chain.risk_score,
            int(alert_risk)
        )

        chain.severity = self.highest_severity(
            chain.severity,
            severity
        )

        # -----------------------------------------------------
        # CHECK EXISTING INCIDENT
        # -----------------------------------------------------

        incident = None

        if chain.incident_id:

            incident = (
                self.incident_manager.get_incident(
                    chain.incident_id
                )
            )

        if incident is None:

            incident = (
                self.incident_manager.find_incident(
                    source_ip,
                    destination_ip
                )
            )

        # -----------------------------------------------------
        # CREATE NEW INCIDENT
        # -----------------------------------------------------

        if incident is None:

            incident = (
                self.incident_manager.create_incident(
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    severity=chain.severity,
                    risk_score=chain.risk_score,
                    attack_type=alert_type,
                    alert_id=alert_id,
                    evidence=alert.get(
                        "evidence"
                    ),
                    timestamp=(
                        event_time.isoformat(
                            timespec="seconds"
                        )
                    ),
                )
            )

            chain.incident_id = (
                incident.incident_id
            )

            return incident

        # -----------------------------------------------------
        # CORRELATE WITH EXISTING INCIDENT
        # -----------------------------------------------------

        chain.incident_id = (
            incident.incident_id
        )

        self.incident_manager.add_alert(
            incident,
            alert,
            risk_score=chain.risk_score,
        )

        return incident

    # ---------------------------------------------------------
    # PROCESS MULTIPLE ALERTS
    # ---------------------------------------------------------

    def process_alerts(
        self,
        alerts: List[Dict[str, Any]],
    ) -> List[Incident]:

        incidents = []

        for alert in alerts:

            incident = self.process_alert(
                alert
            )

            if incident is not None:

                if (
                    incident.incident_id
                    not in {
                        item.incident_id
                        for item in incidents
                    }
                ):

                    incidents.append(
                        incident
                    )

        return incidents

    # ---------------------------------------------------------
    # GET ATTACK CHAIN
    # ---------------------------------------------------------

    def get_attack_chain(
        self,
        source_ip: str,
        destination_ip: str,
    ) -> Optional[AttackChain]:

        return self.chains.get(
            (
                source_ip,
                destination_ip
            )
        )

    # ---------------------------------------------------------
    # GET ACTIVE CHAINS
    # ---------------------------------------------------------

    def get_active_chains(
        self
    ) -> List[AttackChain]:

        return [
            chain
            for chain in self.chains.values()
            if chain.incident_id
        ]

    # ---------------------------------------------------------
    # SUMMARY
    # ---------------------------------------------------------

    def get_summary(self) -> Dict[str, Any]:

        return {
            "total_chains": len(
                self.chains
            ),

            "active_chains": len(
                self.get_active_chains()
            ),

            "tracked_events": sum(
                len(events)
                for events in self.events.values()
            ),

            "incidents": len(
                self.incident_manager.incidents
            ),
        }

    # ---------------------------------------------------------
    # RESET
    # ---------------------------------------------------------

    def reset(self) -> None:

        self.events.clear()

        self.chains.clear()