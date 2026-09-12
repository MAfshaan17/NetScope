"""
NetScope V2.0 - Investigation Engine
Automated incident investigation and explainable findings.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class InvestigationReport:
    incident_id: str
    source_ip: str
    destination_ip: str
    risk_score: int
    severity: str
    attack_chain: list[str] = field(default_factory=list)
    alert_ids: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    recommended_actions: list[str] = field(default_factory=list)
    confidence: str = "MEDIUM"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self):
        return {
            "incident_id": self.incident_id,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "attack_chain": list(self.attack_chain),
            "alert_ids": list(self.alert_ids),
            "findings": list(self.findings),
            "evidence": self.evidence,
            "recommended_actions": list(self.recommended_actions),
            "confidence": self.confidence,
            "timestamp": self.timestamp,
        }


class InvestigationEngine:
    """Builds a deterministic investigation report from SOC evidence."""

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
        alerts = alerts or []
        flows = flows or []
        threat_matches = threat_matches or []

        incident_id = self._get(incident, "incident_id", "UNKNOWN")
        source_ip = self._get(incident, "source_ip", "")
        destination_ip = self._get(incident, "destination_ip", "")
        risk_score = int(self._get(incident, "risk_score", 0) or 0)
        severity = str(self._get(incident, "severity", "LOW")).upper()

        alert_ids = []
        attack_chain = []
        findings = []
        protocols = set()
        ports = set()

        for alert in alerts:
            aid = self._get(alert, "alert_id")
            if aid and aid not in alert_ids:
                alert_ids.append(aid)

            attack_type = (
                self._get(alert, "alert_type")
                or self._get(alert, "rule_id")
                or "UNKNOWN"
            )
            attack_type = str(attack_type)
            if attack_type not in attack_chain:
                attack_chain.append(attack_type)

            ev = self._get(alert, "evidence", {}) or {}
            for port in ev.get("ports", []) or []:
                ports.add(port)
            protocol = ev.get("protocol")
            if protocol:
                protocols.add(protocol)

            desc = self._get(alert, "description")
            if desc and desc not in findings:
                findings.append(str(desc))

        for flow in flows:
            protocol = self._get(flow, "protocol")
            if protocol:
                protocols.add(protocol)
            for key in ("source_port", "destination_port"):
                value = self._get(flow, key)
                if value is not None:
                    ports.add(value)

        if threat_matches:
            findings.append("Threat-intelligence evidence matched network traffic.")

        if attack_chain:
            findings.append(
                "Attack chain contains: " + " -> ".join(attack_chain)
            )

        if risk_score >= 75:
            confidence = "HIGH"
        elif risk_score >= 50 or len(alerts) >= 2:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        evidence = {
            "alert_count": len(alerts),
            "flow_count": len(flows),
            "protocols": sorted(str(x) for x in protocols),
            "ports": sorted(ports, key=lambda x: str(x)),
            "threat_intel_match_count": len(threat_matches),
            "attacker_profile": self._to_dict(attacker_profile),
            "victim_profile": self._to_dict(victim_profile),
            "timeline": self._to_dict(timeline),
        }

        actions = self.recommend_actions(
            severity=severity,
            risk_score=risk_score,
            attack_chain=attack_chain,
            threat_match_count=len(threat_matches),
        )

        return InvestigationReport(
            incident_id=incident_id,
            source_ip=source_ip,
            destination_ip=destination_ip,
            risk_score=risk_score,
            severity=severity,
            attack_chain=attack_chain,
            alert_ids=alert_ids,
            findings=findings,
            evidence=evidence,
            recommended_actions=actions,
            confidence=confidence,
        )

    def recommend_actions(
        self, severity, risk_score, attack_chain, threat_match_count=0
    ):
        actions = []

        if risk_score >= 75 or severity == "CRITICAL":
            actions.extend([
                "ISOLATE_SOURCE",
                "BLOCK_SOURCE_IP",
                "PRESERVE_EVIDENCE",
                "ESCALATE_INCIDENT",
            ])
        elif risk_score >= 50 or severity == "HIGH":
            actions.extend([
                "BLOCK_SOURCE_IP",
                "PRESERVE_EVIDENCE",
                "ESCALATE_INCIDENT",
            ])
        elif risk_score >= 25 or severity == "MEDIUM":
            actions.extend([
                "INCREASE_MONITORING",
                "PRESERVE_EVIDENCE",
            ])
        else:
            actions.append("CONTINUE_MONITORING")

        if "PORT_SCAN" in attack_chain or "Possible Port Scan" in attack_chain:
            if "INCREASE_MONITORING" not in actions:
                actions.append("INCREASE_MONITORING")

        if threat_match_count > 0 and "PRESERVE_EVIDENCE" not in actions:
            actions.append("PRESERVE_EVIDENCE")

        return list(dict.fromkeys(actions))

    @staticmethod
    def _get(obj, key, default=None):
        if obj is None:
            return default
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    @staticmethod
    def _to_dict(obj):
        if obj is None:
            return None
        if hasattr(obj, "to_dict"):
            return obj.to_dict()
        if isinstance(obj, dict):
            return obj
        return str(obj)
