"""
NetScope Threat Intelligence Integration
V1.9.2

Converts ThreatIntelEngine matches into SOC alerts while keeping TI as
an authoritative risk signal.
"""

from datetime import datetime
from typing import Any


class ThreatIntelIntegration:
    RULE_ID = "NS-1008"

    def __init__(self, threat_intel_engine):
        self.threat_intel = threat_intel_engine
        self._alerted_keys: set[tuple[str, str, str]] = set()

    @staticmethod
    def _severity(classification: str) -> str:
        return {
            "MALICIOUS": "CRITICAL",
            "SUSPICIOUS": "HIGH",
        }.get(str(classification).upper(), "LOW")

    def match_to_alert(
        self,
        match: dict[str, Any],
        source_ip: str,
        destination_ip: str,
    ) -> dict[str, Any] | None:
        if not match or not match.get("matched"):
            return None

        classification = str(
            match.get("classification", "")
        ).upper()

        if classification not in {"MALICIOUS", "SUSPICIOUS"}:
            return None

        matched_ip = str(match.get("ip", destination_ip))
        key = (source_ip, destination_ip, matched_ip)

        if key in self._alerted_keys:
            return None

        self._alerted_keys.add(key)

        severity = self._severity(classification)
        confidence = str(match.get("confidence", "LOW")).upper()

        return {
            "alert_type": "Threat Intelligence Match",
            "severity": severity,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "description": (
                f"Threat intelligence matched {matched_ip}: "
                f"{classification}"
            ),
            "evidence": {
                **dict(match.get("evidence", {})),
                "matched_ip": matched_ip,
                "classification": classification,
                "confidence": confidence,
                "source": match.get("source", "LOCAL"),
                "tags": match.get("tags", []),
                "detection_mode": "THREAT_INTELLIGENCE",
            },
            "rule_id": self.RULE_ID,
            "confidence": confidence,
            "timestamp": match.get(
                "timestamp", datetime.now().isoformat()
            ),
            "alert_id": f"NS-TI-{len(self._alerted_keys):04d}",
            "status": "OPEN",
            "suppressed_count": 0,
        }

    def inspect_packet(
        self,
        source_ip: str,
        destination_ip: str,
    ) -> list[dict[str, Any]]:
        alerts = []
        for match in self.threat_intel.inspect_packet(
            source_ip, destination_ip
        ):
            alert = self.match_to_alert(
                match, source_ip, destination_ip
            )
            if alert is not None:
                alerts.append(alert)
        return alerts

    def reset(self) -> None:
        self._alerted_keys.clear()
        self.threat_intel.reset_matches()
