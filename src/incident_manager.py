"""
NetScope V1.8.1
Incident Management System

Creates, tracks, updates and resolves security incidents
generated from detection/risk alerts.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
import json
from pathlib import Path


@dataclass
class Incident:
    incident_id: str
    severity: str
    risk_score: int

    source_ip: str
    destination_ip: str

    status: str = "OPEN"

    attack_types: List[str] = field(default_factory=list)
    alert_ids: List[str] = field(default_factory=list)

    evidence: List[Dict[str, Any]] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)

    first_seen: str = ""
    last_seen: str = ""

    created_at: str = ""
    updated_at: str = ""

    suppressed_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "status": self.status,
            "attack_types": self.attack_types,
            "alert_ids": self.alert_ids,
            "evidence": self.evidence,
            "timeline": self.timeline,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "suppressed_count": self.suppressed_count,
        }


class IncidentManager:

    def __init__(self, log_directory: Optional[str] = None):

        self.incidents: List[Incident] = []

        self.incident_counter = 0

        self.log_directory = Path(
            log_directory
            if log_directory
            else "logs"
        )

        self.log_directory.mkdir(
            parents=True,
            exist_ok=True
        )

        self.incident_file = (
            self.log_directory / "incidents.json"
        )

    # ---------------------------------------------------------
    # INCIDENT ID
    # ---------------------------------------------------------

    def _generate_incident_id(self) -> str:

        self.incident_counter += 1

        return f"NS-INC-{self.incident_counter:04d}"

    # ---------------------------------------------------------
    # TIME
    # ---------------------------------------------------------

    @staticmethod
    def _timestamp() -> str:
        return datetime.now().isoformat(timespec="seconds")

    # ---------------------------------------------------------
    # SEVERITY
    # ---------------------------------------------------------

    @staticmethod
    def _severity_rank(severity: str) -> int:

        ranks = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }

        return ranks.get(
            str(severity).upper(),
            1
        )

    # ---------------------------------------------------------
    # CREATE INCIDENT
    # ---------------------------------------------------------

    def create_incident(
        self,
        source_ip: str,
        destination_ip: str,
        severity: str,
        risk_score: int,
        attack_type: Optional[str] = None,
        alert_id: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None,
        timestamp: Optional[str] = None,
    ) -> Incident:

        now = timestamp or self._timestamp()

        incident = Incident(
            incident_id=self._generate_incident_id(),

            severity=str(severity).upper(),

            risk_score=int(risk_score),

            source_ip=source_ip,

            destination_ip=destination_ip,

            status="OPEN",

            attack_types=(
                [attack_type]
                if attack_type
                else []
            ),

            alert_ids=(
                [alert_id]
                if alert_id
                else []
            ),

            evidence=(
                [evidence]
                if evidence
                else []
            ),

            timeline=[],

            first_seen=now,

            last_seen=now,

            created_at=now,

            updated_at=now,
        )

        # Add first timeline event
        incident.timeline.append(
            {
                "timestamp": now,
                "event": "INCIDENT_CREATED",
                "description": (
                    f"Incident {incident.incident_id} created"
                ),
            }
        )

        self.incidents.append(incident)

        self.save()

        return incident

    # ---------------------------------------------------------
    # FIND INCIDENT
    # ---------------------------------------------------------

    def find_incident(
        self,
        source_ip: str,
        destination_ip: str,
    ) -> Optional[Incident]:

        for incident in reversed(self.incidents):

            if (
                incident.source_ip == source_ip
                and
                incident.destination_ip == destination_ip
                and
                incident.status != "RESOLVED"
            ):
                return incident

        return None

    # ---------------------------------------------------------
    # ADD ALERT TO INCIDENT
    # ---------------------------------------------------------

    def add_alert(
        self,
        incident: Incident,
        alert: Dict[str, Any],
        risk_score: Optional[int] = None,
    ) -> Incident:

        timestamp = alert.get(
            "timestamp",
            self._timestamp()
        )

        alert_id = alert.get(
            "alert_id"
        )

        alert_type = alert.get(
            "alert_type",
            alert.get("rule_id", "UNKNOWN")
        )

        severity = str(
            alert.get(
                "severity",
                "LOW"
            )
        ).upper()

        # -----------------------------------------------------
        # ALERT ID
        # -----------------------------------------------------

        if alert_id and alert_id not in incident.alert_ids:

            incident.alert_ids.append(alert_id)

        # -----------------------------------------------------
        # ATTACK TYPE
        # -----------------------------------------------------

        if alert_type not in incident.attack_types:

            incident.attack_types.append(
                alert_type
            )

        # -----------------------------------------------------
        # EVIDENCE
        # -----------------------------------------------------

        evidence = alert.get(
            "evidence"
        )

        if evidence:

            incident.evidence.append(
                {
                    "alert_id": alert_id,
                    "alert_type": alert_type,
                    "evidence": evidence,
                }
            )

        # -----------------------------------------------------
        # RISK
        # -----------------------------------------------------

        if risk_score is not None:

            incident.risk_score = max(
                incident.risk_score,
                int(risk_score)
            )

        # -----------------------------------------------------
        # SEVERITY ESCALATION
        # -----------------------------------------------------

        if (
            self._severity_rank(severity)
            >
            self._severity_rank(incident.severity)
        ):

            old_severity = incident.severity

            incident.severity = severity

            incident.timeline.append(
                {
                    "timestamp": timestamp,
                    "event": "SEVERITY_ESCALATED",
                    "description": (
                        f"Severity escalated "
                        f"from {old_severity} "
                        f"to {severity}"
                    ),
                }
            )

        # -----------------------------------------------------
        # TIMELINE
        # -----------------------------------------------------

        incident.timeline.append(
            {
                "timestamp": timestamp,
                "event": "ALERT_CORRELATED",
                "alert_id": alert_id,
                "alert_type": alert_type,
                "severity": severity,
            }
        )

        # -----------------------------------------------------
        # TIMES
        # -----------------------------------------------------

        incident.last_seen = timestamp

        incident.updated_at = self._timestamp()

        self.save()

        return incident

    # ---------------------------------------------------------
    # UPDATE STATUS
    # ---------------------------------------------------------

    def update_status(
        self,
        incident_id: str,
        status: str,
    ) -> Optional[Incident]:

        valid_statuses = {
            "OPEN",
            "INVESTIGATING",
            "RESOLVED",
        }

        status = str(status).upper()

        if status not in valid_statuses:

            raise ValueError(
                f"Invalid status: {status}. "
                f"Use OPEN, INVESTIGATING or RESOLVED."
            )

        incident = self.get_incident(
            incident_id
        )

        if incident is None:

            return None

        old_status = incident.status

        incident.status = status

        now = self._timestamp()

        incident.updated_at = now

        incident.timeline.append(
            {
                "timestamp": now,
                "event": "STATUS_CHANGED",
                "description": (
                    f"Status changed from "
                    f"{old_status} to {status}"
                ),
            }
        )

        self.save()

        return incident

    # ---------------------------------------------------------
    # SUPPRESSION
    # ---------------------------------------------------------

    def add_suppression(
        self,
        incident_id: str,
        count: int = 1,
    ) -> Optional[Incident]:

        incident = self.get_incident(
            incident_id
        )

        if incident is None:

            return None

        incident.suppressed_count += int(count)

        incident.updated_at = self._timestamp()

        self.save()

        return incident

    # ---------------------------------------------------------
    # GET INCIDENT
    # ---------------------------------------------------------

    def get_incident(
        self,
        incident_id: str,
    ) -> Optional[Incident]:

        for incident in self.incidents:

            if incident.incident_id == incident_id:

                return incident

        return None

    # ---------------------------------------------------------
    # ACTIVE INCIDENTS
    # ---------------------------------------------------------

    def get_active_incidents(self) -> List[Incident]:

        return [
            incident
            for incident in self.incidents
            if incident.status != "RESOLVED"
        ]

    # ---------------------------------------------------------
    # RESOLVE
    # ---------------------------------------------------------

    def resolve_incident(
        self,
        incident_id: str,
    ) -> Optional[Incident]:

        return self.update_status(
            incident_id,
            "RESOLVED"
        )

    # ---------------------------------------------------------
    # SUMMARY
    # ---------------------------------------------------------

    def get_summary(self) -> Dict[str, Any]:

        severity_counts = {
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0,
        }

        status_counts = {
            "OPEN": 0,
            "INVESTIGATING": 0,
            "RESOLVED": 0,
        }

        for incident in self.incidents:

            severity_counts[
                incident.severity
            ] = (
                severity_counts.get(
                    incident.severity,
                    0
                ) + 1
            )

            status_counts[
                incident.status
            ] = (
                status_counts.get(
                    incident.status,
                    0
                ) + 1
            )

        return {
            "total_incidents": len(
                self.incidents
            ),

            "active_incidents": len(
                self.get_active_incidents()
            ),

            "severity_counts":
                severity_counts,

            "status_counts":
                status_counts,
        }

    # ---------------------------------------------------------
    # SAVE
    # ---------------------------------------------------------

    def save(self) -> None:

        data = [
            incident.to_dict()
            for incident in self.incidents
        ]

        with open(
            self.incident_file,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                data,
                file,
                indent=2,
            )

    # ---------------------------------------------------------
    # LOAD
    # ---------------------------------------------------------

    def load(self) -> None:

        if not self.incident_file.exists():

            return

        try:

            with open(
                self.incident_file,
                "r",
                encoding="utf-8",
            ) as file:

                data = json.load(file)

            self.incidents = []

            for item in data:

                incident = Incident(
                    incident_id=item[
                        "incident_id"
                    ],

                    severity=item[
                        "severity"
                    ],

                    risk_score=item[
                        "risk_score"
                    ],

                    source_ip=item[
                        "source_ip"
                    ],

                    destination_ip=item[
                        "destination_ip"
                    ],

                    status=item.get(
                        "status",
                        "OPEN"
                    ),

                    attack_types=item.get(
                        "attack_types",
                        []
                    ),

                    alert_ids=item.get(
                        "alert_ids",
                        []
                    ),

                    evidence=item.get(
                        "evidence",
                        []
                    ),

                    timeline=item.get(
                        "timeline",
                        []
                    ),

                    first_seen=item.get(
                        "first_seen",
                        ""
                    ),

                    last_seen=item.get(
                        "last_seen",
                        ""
                    ),

                    created_at=item.get(
                        "created_at",
                        ""
                    ),

                    updated_at=item.get(
                        "updated_at",
                        ""
                    ),

                    suppressed_count=item.get(
                        "suppressed_count",
                        0
                    ),
                )

                self.incidents.append(
                    incident
                )

            # Restore counter
            self.incident_counter = len(
                self.incidents
            )

        except (
            json.JSONDecodeError,
            OSError,
            KeyError,
            TypeError,
            ValueError,
        ):

            # Do not crash NetScope because
            # of corrupted historical data.
            self.incidents = []

            self.incident_counter = 0

    # ---------------------------------------------------------
    # RESET
    # ---------------------------------------------------------

    def reset(self) -> None:

        self.incidents.clear()

        self.incident_counter = 0

        self.save()