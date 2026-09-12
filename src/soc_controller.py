"""
NetScope V1.8.7
SOC Orchestration Layer

Connects:
Risk -> Correlation -> Incidents -> Timeline -> Profiles -> Storage -> Dashboard.
"""

from typing import Any, Dict, Iterable, Optional

from .incident_manager import IncidentManager
from .correlation_engine import CorrelationEngine
from .attack_timeline import AttackTimeline
from .profile_engine import ProfileEngine
from .soc_storage import SOCStorage


class SOCController:

    def __init__(
        self,
        logger=None,
        dashboard=None,
        log_directory="logs",
    ):
        self.logger = logger
        self.dashboard = dashboard

        self.incident_manager = IncidentManager(
            log_directory=log_directory
        )
        self.incident_manager.load()

        self.correlation_engine = CorrelationEngine(
            incident_manager=self.incident_manager
        )

        self.timeline = AttackTimeline()
        self.profile_engine = ProfileEngine()
        self.storage = SOCStorage(
            log_directory=log_directory
        )

        self._processed_alert_keys = set()
        self._restore_profiles()

        # Restore timeline information from persisted incidents.
        for incident in self.incident_manager.incidents:
            self.timeline.load_incident(incident)

    # ------------------------------------------------------------
    # PERSISTED PROFILES
    # ------------------------------------------------------------

    def _restore_profiles(self):
        state = self.storage.load_state()

        for item in state.get("attackers", []):
            ip = str(item.get("ip", "UNKNOWN"))
            profile = self.profile_engine.get_attacker(ip)

            profile.risk_score = int(item.get("risk_score", 0))
            profile.severity = item.get("severity", "LOW")
            profile.alert_count = int(item.get("alert_count", 0))
            profile.incident_count = int(item.get("incident_count", 0))

            profile.port_scan_count = int(
                item.get("port_scan_count", 0)
            )
            profile.syn_scan_count = int(
                item.get("syn_scan_count", 0)
            )
            profile.dns_burst_count = int(
                item.get("dns_burst_count", 0)
            )
            profile.connection_rate_count = int(
                item.get("connection_rate_count", 0)
            )
            profile.traffic_burst_count = int(
                item.get("traffic_burst_count", 0)
            )
            profile.high_activity_count = int(
                item.get("high_activity_count", 0)
            )

            profile.targets.update(
                str(value)
                for value in item.get("targets", [])
            )

            for value in item.get("ports", []):
                try:
                    profile.ports.add(int(value))
                except (TypeError, ValueError):
                    pass

            profile.protocols.update(
                str(value)
                for value in item.get("protocols", [])
            )

            profile.first_seen = item.get("first_seen", "")
            profile.last_seen = item.get("last_seen", "")

        for item in state.get("victims", []):
            ip = str(item.get("ip", "UNKNOWN"))
            profile = self.profile_engine.get_victim(ip)

            profile.risk_score = int(item.get("risk_score", 0))
            profile.severity = item.get("severity", "LOW")
            profile.attack_count = int(
                item.get("attack_count", 0)
            )
            profile.incident_count = int(
                item.get("incident_count", 0)
            )

            profile.sources.update(
                str(value)
                for value in item.get("sources", [])
            )

            for value in item.get("targeted_ports", []):
                try:
                    profile.targeted_ports.add(int(value))
                except (TypeError, ValueError):
                    pass

            profile.protocols.update(
                str(value)
                for value in item.get("protocols", [])
            )

            profile.attack_types.update(
                str(value)
                for value in item.get("attack_types", [])
            )

            profile.first_seen = item.get("first_seen", "")
            profile.last_seen = item.get("last_seen", "")

    # ------------------------------------------------------------
    # ALERT KEY
    # ------------------------------------------------------------

    @staticmethod
    def _alert_key(alert: Dict[str, Any]):
        alert_id = alert.get("alert_id")

        if alert_id:
            return ("ID", str(alert_id))

        return (
            "FINGERPRINT",
            str(alert.get("rule_id", "")),
            str(alert.get("alert_type", "")),
            str(alert.get("source_ip", "")),
            str(alert.get("destination_ip", "")),
            str(alert.get("timestamp", "")),
        )

    # ------------------------------------------------------------
    # PROCESS ALERTS
    # ------------------------------------------------------------

    def process_alerts(
        self,
        alerts: Iterable[Dict[str, Any]],
        risk_score: int = 0,
    ):
        incidents = []

        for alert in alerts or []:
            if not isinstance(alert, dict):
                continue

            key = self._alert_key(alert)

            if key in self._processed_alert_keys:
                continue

            self._processed_alert_keys.add(key)

            enriched = dict(alert)

            if risk_score:
                enriched["risk_score"] = max(
                    int(enriched.get("risk_score", 0) or 0),
                    int(risk_score),
                )

            incident_before = self.incident_manager.find_incident(
                str(enriched.get("source_ip", "UNKNOWN")),
                str(enriched.get("destination_ip", "UNKNOWN")),
            )

            incident = self.correlation_engine.process_alert(
                enriched,
                risk_score=risk_score,
            )

            if incident is None:
                continue

            incidents.append(incident)

            # Timeline.
            self.timeline.add_alert(enriched)

            # Profiles.
            self.profile_engine.process_alert(
                enriched,
                risk_score=int(risk_score or enriched.get("risk_score", 0) or 0),
            )

            # Only count a profile incident when this was genuinely
            # a new incident.
            if incident_before is None:
                self.profile_engine.process_incident(incident)

            # Dashboard incident.
            if self.dashboard is not None:
                self.dashboard.update_incident(
                    incident.to_dict()
                )

            # Logger.
            if self.logger is not None:
                try:
                    self.logger.log_alerts([enriched])
                except Exception:
                    pass

        if incidents:
            self.save()

        return incidents

    # ------------------------------------------------------------
    # PACKET
    # ------------------------------------------------------------

    def process_packet(
        self,
        alerts,
        risk,
        source_ip: str,
        destination_ip: str,
        destination_port=None,
        protocol=None,
    ):
        risk_score = 0

        if isinstance(risk, dict):
            risk_score = int(risk.get("score", 0) or 0)

        enriched_alerts = []

        for alert in alerts or []:
            enriched = dict(alert)

            enriched.setdefault("source_ip", source_ip)
            enriched.setdefault("destination_ip", destination_ip)

            if destination_port is not None:
                enriched.setdefault(
                    "destination_port",
                    destination_port,
                )

            if protocol:
                enriched.setdefault("protocol", protocol)

            if risk_score:
                enriched["risk_score"] = max(
                    int(enriched.get("risk_score", 0) or 0),
                    risk_score,
                )

            enriched_alerts.append(enriched)

        return self.process_alerts(
            enriched_alerts,
            risk_score=risk_score,
        )

    # ------------------------------------------------------------
    # SAVE
    # ------------------------------------------------------------

    def save(self):
        self.incident_manager.save()

        self.storage.save_soc(
            self.incident_manager.incidents,
            self.profile_engine.attackers,
            self.profile_engine.victims,
        )

    # ------------------------------------------------------------
    # SUMMARY
    # ------------------------------------------------------------

    def get_summary(self):
        incident_summary = self.incident_manager.get_summary()
        profile_summary = self.profile_engine.get_summary()
        correlation_summary = self.correlation_engine.get_summary()
        timeline_summary = self.timeline.get_summary()

        return {
            "incidents": incident_summary["total_incidents"],
            "active_incidents": incident_summary["active_incidents"],
            "attackers": profile_summary["attacker_count"],
            "victims": profile_summary["victim_count"],
            "timeline_events": timeline_summary["event_count"],
            "attack_stages": timeline_summary["attack_stages"],
            "correlation_chains": correlation_summary["total_chains"],
        }
