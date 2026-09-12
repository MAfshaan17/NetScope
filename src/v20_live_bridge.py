"""
NetScope V2.0 - Live SOC Bridge
Connects the existing V1.9.x SOC pipeline to V2.0 investigation,
response planning and evidence preservation.
"""

from types import SimpleNamespace

from .v20_soc import V20SOC


class LiveV20Bridge:
    def __init__(self, log_directory="logs", dashboard=None):
        self.v20 = V20SOC(log_directory=log_directory)
        self.dashboard = dashboard
        self.last_report = None
        self.last_plan = None

    def investigate(
        self,
        incident,
        alerts=None,
        flows=None,
        timeline=None,
        attacker_profile=None,
        victim_profile=None,
        threat_matches=None,
    ):
        report, plan = self.v20.investigate_incident(
            incident=incident,
            alerts=alerts,
            flows=flows,
            timeline=timeline,
            attacker_profile=attacker_profile,
            victim_profile=victim_profile,
            threat_matches=threat_matches,
        )

        # Backward compatibility: older V2.0 tests/callers expect the
        # investigation report itself to expose approval_required.
        report = self._ensure_report_compat(report, plan)

        self.last_report = report
        self.last_plan = plan
        self._update_dashboard(report, plan)
        return report, plan

    def investigate_active_incidents(
        self,
        incident_manager,
        alert_lookup=None,
        flow_lookup=None,
        timeline_lookup=None,
        profile_lookup=None,
        threat_lookup=None,
    ):
        """Investigate every currently active incident."""
        get_active = getattr(incident_manager, "get_active_incidents", None)
        if not callable(get_active):
            raise AttributeError(
                "incident_manager must provide get_active_incidents()"
            )

        incidents = get_active() or []
        alert_lookup = alert_lookup or {}
        flow_lookup = flow_lookup or {}
        timeline_lookup = timeline_lookup or {}
        profile_lookup = profile_lookup or {}
        threat_lookup = threat_lookup or {}

        results = []

        for incident in incidents:
            incident_id = self._value(incident, "incident_id")

            profile_data = self._lookup(profile_lookup, incident_id)
            attacker_profile = None
            victim_profile = None

            if isinstance(profile_data, dict):
                attacker_profile = profile_data.get(
                    "attacker", profile_data.get("attacker_profile")
                )
                victim_profile = profile_data.get(
                    "victim", profile_data.get("victim_profile")
                )

            report, plan = self.investigate(
                incident=incident,
                alerts=self._lookup(alert_lookup, incident_id) or [],
                flows=self._lookup(flow_lookup, incident_id) or [],
                timeline=self._lookup(timeline_lookup, incident_id),
                attacker_profile=attacker_profile,
                victim_profile=victim_profile,
                threat_matches=self._lookup(threat_lookup, incident_id) or [],
            )

            # Keep the legacy/test-compatible tuple shape:
            # (incident, report, plan).
            # Some older callers/tests expect the incident item to expose
            # attributes (e.g. incident.incident_id), while the live SOC
            # may supply plain dictionaries. Normalize dictionaries only
            # for the returned compatibility view; the original incident
            # is still passed unchanged into V2.0 investigation.
            result_incident = self._as_object(incident)
            results.append((result_incident, report, plan))

        return results

    def _update_dashboard(self, report, plan):
        """Push V2.0 investigation results into the existing dashboard."""
        if self.dashboard is None:
            return

        update_incident = getattr(self.dashboard, "update_incident", None)
        if callable(update_incident):
            update_incident(
                {
                    "incident_id": self._value(report, "incident_id"),
                    "severity": self._value(report, "severity"),
                    "risk_score": self._value(report, "risk_score", 0),
                    "source_ip": self._value(report, "source_ip"),
                    "destination_ip": self._value(report, "destination_ip"),
                    "status": "INVESTIGATING",
                    "attack_types": self._value(report, "attack_chain", []),
                    "alert_ids": self._value(report, "alert_ids", []),
                    "evidence": self._value(report, "evidence", {}),
                    "timeline": self._value(report, "timeline", []),
                }
            )

        refresh = getattr(self.dashboard, "refresh", None)
        if callable(refresh):
            refresh()

    @staticmethod
    def _ensure_report_compat(report, plan):
        """Ensure reports expose the approval_required compatibility field."""
        if hasattr(report, "approval_required"):
            return report

        approval_required = getattr(plan, "approval_required", None)
        if approval_required is None and isinstance(plan, dict):
            approval_required = plan.get("approval_required")
        if approval_required is None:
            # V2.0 response actions are approval-gated by design.
            approval_required = True

        try:
            setattr(report, "approval_required", bool(approval_required))
            return report
        except (AttributeError, TypeError):
            # Frozen/slots-based report compatibility fallback.
            data = {}
            if hasattr(report, "__dataclass_fields__"):
                data = {name: getattr(report, name) for name in report.__dataclass_fields__}
            elif hasattr(report, "__dict__"):
                data = dict(report.__dict__)
            data["approval_required"] = bool(approval_required)
            return SimpleNamespace(**data)

    @staticmethod
    def _as_object(obj):
        """Return an attribute-accessible view for dict incidents."""
        if isinstance(obj, dict):
            return SimpleNamespace(**obj)
        return obj

    @staticmethod
    def _value(obj, name, default=None):
        if isinstance(obj, dict):
            return obj.get(name, default)
        return getattr(obj, name, default)

    @staticmethod
    def _lookup(mapping, key):
        return mapping.get(key) if hasattr(mapping, "get") else None
