"""
NetScope V2.0 - Evidence Manager
Stores investigation evidence under logs/incidents/<incident_id>/.
"""

import json
import os
from pathlib import Path
from datetime import datetime, timezone


class EvidenceManager:
    def __init__(self, log_directory="logs"):
        self.root = Path(log_directory) / "incidents"
        self.root.mkdir(parents=True, exist_ok=True)

    def save_incident_evidence(
        self,
        incident_id,
        incident,
        investigation,
        response_plan,
        alerts=None,
        flows=None,
    ):
        directory = self.root / str(incident_id)
        directory.mkdir(parents=True, exist_ok=True)

        self._write(directory / "incident.json", self._dict(incident))
        self._write(directory / "investigation_report.json",
                    self._dict(investigation))
        self._write(directory / "response_plan.json",
                    self._dict(response_plan))
        self._write(directory / "alerts.json",
                    [self._dict(x) for x in (alerts or [])])
        self._write(directory / "flows.json",
                    [self._dict(x) for x in (flows or [])])

        manifest = {
            "incident_id": str(incident_id),
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "files": [
                "incident.json",
                "investigation_report.json",
                "response_plan.json",
                "alerts.json",
                "flows.json",
            ],
        }
        self._write(directory / "manifest.json", manifest)
        return str(directory)

    @staticmethod
    def _dict(value):
        if hasattr(value, "to_dict"):
            return value.to_dict()
        return value

    @staticmethod
    def _write(path, data):
        temp = path.with_suffix(path.suffix + ".tmp")
        with temp.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, default=str)
        os.replace(temp, path)
