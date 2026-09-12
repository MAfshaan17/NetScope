"""
NetScope V2.0 - Safe Response Engine

This module ONLY recommends response actions.
It deliberately does not modify firewall rules, routes, processes,
or host configuration automatically.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class ResponsePlan:
    incident_id: str
    severity: str
    risk_score: int
    approval_required: bool = True
    actions: list[str] = field(default_factory=list)
    rationale: list[str] = field(default_factory=list)
    status: str = "PENDING_APPROVAL"
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self):
        return {
            "incident_id": self.incident_id,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "approval_required": self.approval_required,
            "actions": self.actions,
            "rationale": self.rationale,
            "status": self.status,
            "created_at": self.created_at,
        }


class ResponseEngine:
    """Creates human-approved response plans."""

    def create_plan(self, investigation):
        incident_id = self._get(investigation, "incident_id", "UNKNOWN")
        severity = str(
            self._get(investigation, "severity", "LOW")
        ).upper()
        score = int(self._get(investigation, "risk_score", 0) or 0)
        actions = list(
            self._get(investigation, "recommended_actions", []) or []
        )

        rationale = []

        if score >= 75:
            rationale.append("Risk score is critical-level.")
        elif score >= 50:
            rationale.append("Risk score is high-level.")
        elif score >= 25:
            rationale.append("Risk score is medium-level.")

        chain = self._get(investigation, "attack_chain", []) or []
        if chain:
            rationale.append(
                "Observed attack chain: " + " -> ".join(map(str, chain))
            )

        if self._get(investigation, "evidence", {}).get(
            "threat_intel_match_count", 0
        ):
            rationale.append("Threat-intelligence evidence is present.")

        return ResponsePlan(
            incident_id=incident_id,
            severity=severity,
            risk_score=score,
            approval_required=True,
            actions=actions,
            rationale=rationale,
        )

    @staticmethod
    def approve(plan):
        data = plan.to_dict() if hasattr(plan, "to_dict") else dict(plan)
        data["status"] = "APPROVED"
        data["approval_required"] = False
        return data

    @staticmethod
    def reject(plan):
        data = plan.to_dict() if hasattr(plan, "to_dict") else dict(plan)
        data["status"] = "REJECTED"
        return data

    @staticmethod
    def _get(obj, key, default=None):
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)
