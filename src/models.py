from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class SecurityAlert:

    alert_type: str
    severity: str

    source_ip: str
    destination_ip: str

    description: str

    evidence: dict[str, Any] = field(
        default_factory=dict
    )

    rule_id: str = "UNKNOWN"

    confidence: Any = "MEDIUM"

    timestamp: str = field(
        default_factory=lambda:
        datetime.now().isoformat(
            timespec="seconds"
        )
    )

    alert_id: str = ""

    def __post_init__(self):

        # Generate alert ID if not supplied
        if not self.alert_id:

            timestamp = datetime.now()

            date_part = timestamp.strftime(
                "%Y%m%d"
            )

            self.alert_id = (
                f"NS-{date_part}-0001"
            )

    def to_dict(self):

        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "description": self.description,
            "evidence": self.evidence,
            "timestamp": self.timestamp
        }