"""
NetScope Risk Scoring Engine
V1.9.2

NS-1006:
Risk Scoring + Suspicious Destination Detection
Threat Intelligence integration.
"""

from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_address
from typing import Any


@dataclass
class RiskAssessment:
    source_ip: str
    destination_ip: str
    score: int
    severity: str
    confidence: str
    signals: list[dict[str, Any]] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    rule_id: str = "NS-1006"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "score": self.score,
            "severity": self.severity,
            "confidence": self.confidence,
            "signals": self.signals,
            "timestamp": self.timestamp,
        }


class RiskEngine:
    """Combines detection, packet, and threat-intelligence signals."""

    DEFAULT_WEIGHTS = {
        "PORT_SCAN": 20,
        "SYN_SCAN": 20,
        "DNS_BURST": 15,
        "TRAFFIC_BURST": 20,
        "HIGH_CONNECTION_RATE": 20,
        "SUSPICIOUS_DESTINATION": 25,
        "UNUSUAL_PORT": 10,
        "UNEXPECTED_PROTOCOL": 10,
        "THREAT_INTEL_MALICIOUS": 30,
        "THREAT_INTEL_SUSPICIOUS": 15,
    }

    DEFAULT_UNUSUAL_PORTS = {
        23, 135, 139, 445, 1433, 1521, 3306, 3389, 5900, 6379, 9200
    }

    def __init__(
        self,
        suspicious_ips: set[str] | None = None,
        unusual_ports: set[int] | None = None,
        unexpected_protocols: set[str] | None = None,
        weights: dict[str, int] | None = None,
    ):
        self.suspicious_ips = suspicious_ips or set()
        self.unusual_ports = (
            unusual_ports if unusual_ports is not None
            else set(self.DEFAULT_UNUSUAL_PORTS)
        )
        self.unexpected_protocols = unexpected_protocols or set()
        self.weights = dict(self.DEFAULT_WEIGHTS)
        if weights:
            self.weights.update(weights)
        self.assessments: list[RiskAssessment] = []

    @staticmethod
    def is_private(ip: str) -> bool:
        try:
            return ip_address(ip).is_private
        except ValueError:
            return False

    @staticmethod
    def is_public(ip: str) -> bool:
        try:
            return ip_address(ip).is_global
        except ValueError:
            return False

    @staticmethod
    def severity_from_score(score: int) -> str:
        if score >= 75:
            return "CRITICAL"
        if score >= 50:
            return "HIGH"
        if score >= 25:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def confidence_from_score(score: int) -> str:
        if score >= 50:
            return "HIGH"
        if score >= 25:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _signal(name: str, description: str, score: int) -> dict[str, Any]:
        return {"name": name, "description": description, "score": score}

    def process_alert(self, alert: dict[str, Any]) -> dict[str, Any] | None:
        mapping = {
            "NS-1001": "PORT_SCAN",
            "NS-1002": "SYN_SCAN",
            "NS-1004": "DNS_BURST",
            "NS-1005": "HIGH_CONNECTION_RATE",
            "NS-1007": "TRAFFIC_BURST",
        }
        signal_type = mapping.get(alert.get("rule_id"))
        if signal_type is None:
            return None
        return {
            "type": signal_type,
            "score": self.weights.get(signal_type, 0),
            "description": alert.get(
                "description", f"{signal_type} detected"
            ),
        }

    def process_threat_intel(
        self, threat_intel: dict[str, Any] | None
    ) -> dict[str, Any] | None:
        """Convert a ThreatIntelEngine result into one risk signal."""
        if not threat_intel or not threat_intel.get("matched"):
            return None

        classification = str(
            threat_intel.get("classification", "")
        ).upper()

        if classification == "MALICIOUS":
            signal_type = "THREAT_INTEL_MALICIOUS"
        elif classification == "SUSPICIOUS":
            signal_type = "THREAT_INTEL_SUSPICIOUS"
        else:
            return None

        score = self.weights.get(signal_type, 0)
        indicator = threat_intel.get("ip", threat_intel.get("matched_ip", "UNKNOWN"))
        confidence = threat_intel.get("confidence", "LOW")

        return {
            "type": signal_type,
            "score": score,
            "description": (
                f"Threat intelligence matched {indicator} as "
                f"{classification} ({confidence} confidence)"
            ),
            "classification": classification,
            "confidence": confidence,
            "source": threat_intel.get("source", "LOCAL"),
            "tags": threat_intel.get("tags", []),
            "evidence": threat_intel.get("evidence", {}),
        }

    def assess_packet(
        self,
        source_ip: str,
        destination_ip: str,
        destination_port: int | None = None,
        protocol: str = "UNKNOWN",
        alerts: list[dict[str, Any]] | None = None,
        threat_intel: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        score = 0
        signals: list[dict[str, Any]] = []
        ti_signal = self.process_threat_intel(threat_intel)

        # If TI has classified the destination, do not double-count the
        # generic suspicious-destination signal for the same IP.
        ti_classified = bool(
            ti_signal and threat_intel and threat_intel.get("matched")
        )

        if destination_ip in self.suspicious_ips and not ti_classified:
            weight = self.weights["SUSPICIOUS_DESTINATION"]
            score += weight
            signals.append(self._signal(
                "SUSPICIOUS_DESTINATION",
                f"Destination {destination_ip} is in the configured suspicious destination list",
                weight,
            ))

        if destination_port is not None:
            try:
                port = int(destination_port)
            except (ValueError, TypeError):
                port = None
            if port is not None and port in self.unusual_ports:
                weight = self.weights["UNUSUAL_PORT"]
                score += weight
                signals.append(self._signal(
                    "UNUSUAL_PORT",
                    f"Destination port {port} is considered unusual",
                    weight,
                ))

        normalized_protocol = str(protocol).upper()
        if (
            self.unexpected_protocols
            and normalized_protocol in self.unexpected_protocols
        ):
            weight = self.weights["UNEXPECTED_PROTOCOL"]
            score += weight
            signals.append(self._signal(
                "UNEXPECTED_PROTOCOL",
                f"Protocol {normalized_protocol} is configured as unexpected",
                weight,
            ))

        if ti_signal is not None:
            score += ti_signal["score"]
            signals.append(self._signal(
                ti_signal["type"],
                ti_signal["description"],
                ti_signal["score"],
            ))
            signals[-1]["classification"] = ti_signal["classification"]
            signals[-1]["confidence"] = ti_signal["confidence"]
            signals[-1]["source"] = ti_signal["source"]
            signals[-1]["tags"] = ti_signal["tags"]
            signals[-1]["evidence"] = ti_signal["evidence"]

        if alerts:
            processed_types = set()
            for alert in alerts:
                signal = self.process_alert(alert)
                if signal is None:
                    continue
                signal_type = signal["type"]
                if signal_type in processed_types:
                    continue
                processed_types.add(signal_type)
                score += signal["score"]
                signals.append(self._signal(
                    signal_type, signal["description"], signal["score"]
                ))

        severity = self.severity_from_score(score)
        confidence = self.confidence_from_score(score)

        assessment = RiskAssessment(
            source_ip=source_ip,
            destination_ip=destination_ip,
            score=score,
            severity=severity,
            confidence=confidence,
            signals=signals,
        )
        result = assessment.to_dict()
        if score > 0:
            self.assessments.append(assessment)
        return result

    def assess_alerts(
        self,
        source_ip: str,
        destination_ip: str,
        alerts: list[dict[str, Any]],
        threat_intel: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self.assess_packet(
            source_ip=source_ip,
            destination_ip=destination_ip,
            alerts=alerts,
            threat_intel=threat_intel,
        )

    def get_summary(self) -> dict[str, Any]:
        if not self.assessments:
            return {
                "total_assessments": 0,
                "highest_score": 0,
                "highest_severity": "LOW",
            }

        highest = max(self.assessments, key=lambda assessment: assessment.score)
        return {
            "total_assessments": len(self.assessments),
            "highest_score": highest.score,
            "highest_severity": highest.severity,
            "highest_source": highest.source_ip,
            "highest_destination": highest.destination_ip,
        }

    def reset(self):
        self.assessments.clear()
