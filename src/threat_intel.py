"""NetScope V1.9.1 - Offline-first Threat Intelligence Engine."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional


@dataclass
class ThreatIntelMatch:
    indicator: str
    indicator_type: str
    classification: str
    confidence: str
    source: str
    description: str = ""
    tags: List[str] = field(default_factory=list)
    matched_ip: Optional[str] = None
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "classification": self.classification,
            "confidence": self.confidence,
            "source": self.source,
            "description": self.description,
            "tags": list(self.tags),
            "matched_ip": self.matched_ip,
            "timestamp": self.timestamp,
        }


class ThreatIntelEngine:
    VALID_CLASSIFICATIONS = {"MALICIOUS", "SUSPICIOUS", "BENIGN"}
    VALID_CONFIDENCE = {"LOW", "MEDIUM", "HIGH"}

    def __init__(
        self,
        ioc_ips: Optional[Dict[str, Dict[str, Any]]] = None,
        suspicious_ips: Optional[Iterable[str]] = None,
        malicious_ips: Optional[Iterable[str]] = None,
        source: str = "LOCAL",
    ):
        self.source = source
        self.ioc_ips: Dict[str, Dict[str, Any]] = {}
        self.matches: List[ThreatIntelMatch] = []

        for ip, data in (ioc_ips or {}).items():
            self.add_ip(ip, **data)
        for ip in suspicious_ips or []:
            self.add_ip(ip, "SUSPICIOUS", "MEDIUM", source)
        for ip in malicious_ips or []:
            self.add_ip(ip, "MALICIOUS", "HIGH", source)

    @staticmethod
    def _timestamp() -> str:
        return datetime.now().isoformat(timespec="seconds")

    @staticmethod
    def _normalize_ip(ip: Any) -> str:
        return str(ip).strip()

    def add_ip(
        self, ip: str, classification: str = "SUSPICIOUS",
        confidence: str = "MEDIUM", source: Optional[str] = None,
        description: str = "", tags: Optional[Iterable[str]] = None,
    ) -> None:
        classification = str(classification).upper()
        confidence = str(confidence).upper()
        if classification not in self.VALID_CLASSIFICATIONS:
            raise ValueError(f"Invalid classification: {classification}")
        if confidence not in self.VALID_CONFIDENCE:
            raise ValueError(f"Invalid confidence: {confidence}")
        self.ioc_ips[self._normalize_ip(ip)] = {
            "classification": classification,
            "confidence": confidence,
            "source": source or self.source,
            "description": description,
            "tags": list(tags or []),
        }

    def remove_ip(self, ip: str) -> bool:
        return self.ioc_ips.pop(self._normalize_ip(ip), None) is not None

    def contains(self, ip: str) -> bool:
        return self._normalize_ip(ip) in self.ioc_ips

    def lookup_ip(self, ip: str) -> Optional[ThreatIntelMatch]:
        normalized = self._normalize_ip(ip)
        record = self.ioc_ips.get(normalized)
        if record is None:
            return None
        match = ThreatIntelMatch(
            indicator=normalized, indicator_type="IP",
            classification=record["classification"],
            confidence=record["confidence"], source=record["source"],
            description=record.get("description", ""),
            tags=list(record.get("tags", [])), matched_ip=normalized,
            timestamp=self._timestamp(),
        )
        self.matches.append(match)
        return match

    def inspect_ip(self, ip: str) -> Dict[str, Any]:
        match = self.lookup_ip(ip)
        if match is None:
            return {
                "matched": False, "ip": self._normalize_ip(ip),
                "classification": "UNKNOWN", "confidence": "LOW",
                "source": None, "description": "", "tags": [],
                "evidence": {"ioc_match": False, "indicator_type": "IP"},
            }
        return {
            "matched": True, "ip": self._normalize_ip(ip),
            "classification": match.classification,
            "confidence": match.confidence, "source": match.source,
            "description": match.description, "tags": list(match.tags),
            "evidence": {
                "ioc_match": True, "indicator_type": "IP",
                "indicator": match.indicator,
                "classification": match.classification,
                "confidence": match.confidence,
                "source": match.source,
                "tags": list(match.tags),
            },
        }

    def inspect_packet(self, source_ip: str, destination_ip: str) -> List[Dict[str, Any]]:
        results = []
        for ip, direction in ((source_ip, "SOURCE"), (destination_ip, "DESTINATION")):
            result = self.inspect_ip(ip)
            if result["matched"]:
                result["direction"] = direction
                results.append(result)
        return results

    def get_summary(self) -> Dict[str, Any]:
        counts = {"MALICIOUS": 0, "SUSPICIOUS": 0, "BENIGN": 0}
        for match in self.matches:
            counts[match.classification] = counts.get(match.classification, 0) + 1
        return {
            "ioc_count": len(self.ioc_ips),
            "match_count": len(self.matches),
            "malicious_matches": counts["MALICIOUS"],
            "suspicious_matches": counts["SUSPICIOUS"],
            "benign_matches": counts["BENIGN"],
            "high_confidence_matches": sum(m.confidence == "HIGH" for m in self.matches),
        }

    def export_iocs(self) -> Dict[str, Dict[str, Any]]:
        return {ip: {**data, "tags": list(data.get("tags", []))}
                for ip, data in self.ioc_ips.items()}

    def reset_matches(self) -> None:
        self.matches.clear()
