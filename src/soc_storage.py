"""
NetScope V1.8.5
SOC Persistence Layer

Persists incidents, attacker profiles, victim profiles,
and SOC metadata across NetScope restarts.
"""

import json
from pathlib import Path
from typing import Any, Dict, Optional


class SOCStorage:

    def __init__(
        self,
        log_directory: Optional[str] = None,
    ):

        self.log_directory = Path(
            log_directory
            if log_directory
            else "logs"
        )

        self.log_directory.mkdir(
            parents=True,
            exist_ok=True
        )

        self.state_file = (
            self.log_directory
            / "soc_state.json"
        )

    # ---------------------------------------------------------
    # SAVE
    # ---------------------------------------------------------

    def save_state(
        self,
        state: Dict[str, Any],
    ) -> None:

        temp_file = (
            self.log_directory
            / "soc_state.tmp"
        )

        with open(
            temp_file,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                state,
                file,
                indent=2,
            )

        temp_file.replace(
            self.state_file
        )

    # ---------------------------------------------------------
    # LOAD
    # ---------------------------------------------------------

    def load_state(
        self,
    ) -> Dict[str, Any]:

        if not self.state_file.exists():

            return {}

        try:

            with open(
                self.state_file,
                "r",
                encoding="utf-8",
            ) as file:

                data = json.load(file)

            if not isinstance(data, dict):

                return {}

            return data

        except (
            OSError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ):

            return {}

    # ---------------------------------------------------------
    # EXISTS
    # ---------------------------------------------------------

    def exists(self) -> bool:

        return self.state_file.exists()

    # ---------------------------------------------------------
    # DELETE
    # ---------------------------------------------------------

    def clear(self) -> None:

        if self.state_file.exists():

            self.state_file.unlink()

    # ---------------------------------------------------------
    # SAVE INCIDENTS
    # ---------------------------------------------------------

    def save_incidents(
        self,
        incidents,
    ) -> None:

        state = self.load_state()

        state["incidents"] = [
            incident.to_dict()
            for incident in incidents
        ]

        self.save_state(state)

    # ---------------------------------------------------------
    # SAVE PROFILES
    # ---------------------------------------------------------

    def save_profiles(
        self,
        attackers,
        victims,
    ) -> None:

        state = self.load_state()

        state["attackers"] = [
            profile.to_dict()
            for profile in attackers.values()
        ]

        state["victims"] = [
            profile.to_dict()
            for profile in victims.values()
        ]

        self.save_state(state)

    # ---------------------------------------------------------
    # SAVE EVERYTHING
    # ---------------------------------------------------------

    def save_soc(
        self,
        incidents,
        attackers,
        victims,
    ) -> None:

        state = {
            "version": "1.8.5",

            "incidents": [
                incident.to_dict()
                for incident in incidents
            ],

            "attackers": [
                profile.to_dict()
                for profile in attackers.values()
            ],

            "victims": [
                profile.to_dict()
                for profile in victims.values()
            ],
        }

        self.save_state(state)

    # ---------------------------------------------------------
    # SUMMARY
    # ---------------------------------------------------------

    def get_summary(
        self,
    ) -> Dict[str, Any]:

        state = self.load_state()

        return {
            "version": state.get(
                "version",
                "UNKNOWN"
            ),

            "incidents": len(
                state.get(
                    "incidents",
                    []
                )
            ),

            "attackers": len(
                state.get(
                    "attackers",
                    []
                )
            ),

            "victims": len(
                state.get(
                    "victims",
                    []
                )
            ),
        }