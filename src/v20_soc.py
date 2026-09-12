"""
NetScope V2.0 - Investigation/Response Orchestrator

Works alongside the existing V1.8/V1.9 SOC stack.
It does not replace detection, correlation, profiles, or the dashboard.
"""

from .investigation_engine import InvestigationEngine
from .response_engine import ResponseEngine
from .evidence_manager import EvidenceManager


class V20SOC:
    def __init__(self, log_directory="logs"):
        self.investigator = InvestigationEngine()
        self.responder = ResponseEngine()
        self.evidence = EvidenceManager(log_directory)
        self.reports = {}
        self.plans = {}

    def investigate_incident(
        self,
        incident,
        alerts=None,
        flows=None,
        timeline=None,
        attacker_profile=None,
        victim_profile=None,
        threat_matches=None,
    ):
        report = self.investigator.investigate(
            incident=incident,
            alerts=alerts,
            flows=flows,
            timeline=timeline,
            attacker_profile=attacker_profile,
            victim_profile=victim_profile,
            threat_matches=threat_matches,
        )
        plan = self.responder.create_plan(report)

        incident_id = report.incident_id
        self.reports[incident_id] = report
        self.plans[incident_id] = plan

        self.evidence.save_incident_evidence(
            incident_id=incident_id,
            incident=incident,
            investigation=report,
            response_plan=plan,
            alerts=alerts,
            flows=flows,
        )

        return report, plan

    def get_report(self, incident_id):
        report = self.reports.get(incident_id)
        return report.to_dict() if report else None

    def get_plan(self, incident_id):
        plan = self.plans.get(incident_id)
        return plan.to_dict() if plan else None

    def get_summary(self):
        return {
            "investigations": len(self.reports),
            "response_plans": len(self.plans),
            "pending_approval": sum(
                1 for p in self.plans.values()
                if p.status == "PENDING_APPROVAL"
            ),
        }
