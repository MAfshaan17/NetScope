"""
NetScope V1.8.6
SOC Dashboard

Rich-based Security Operations Center dashboard.
"""

from collections import Counter, deque
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


class NetworkDashboard:

    def __init__(
        self,
        max_packets: int = 12,
        max_alerts: int = 10,
    ):

        # -----------------------------------------------------
        # NETWORK
        # -----------------------------------------------------

        self.packet_count = 0
        self.total_bytes = 0

        self.protocol_counts = Counter()

        self.recent_packets = deque(
            maxlen=max_packets
        )

        # -----------------------------------------------------
        # SECURITY
        # -----------------------------------------------------

        self.recent_alerts = deque(
            maxlen=max_alerts
        )

        self.alert_count = 0
        self.suppressed_count = 0

        self.severity_counts = Counter()
        self.rule_counts = Counter()

        # -----------------------------------------------------
        # SOC
        # -----------------------------------------------------

        self.incident_count = 0
        self.active_incidents = 0

        self.critical_incidents = 0
        self.high_incidents = 0
        self.medium_incidents = 0
        self.low_incidents = 0

        self.risk_score = 0

        self.recent_incidents = deque(
            maxlen=8
        )

        self.attackers = []
        self.victims = []

        self.timeline_events = deque(
            maxlen=10
        )

        # -----------------------------------------------------
        # FLOWS
        # -----------------------------------------------------

        self.flow_count = 0

    # =========================================================
    # PACKET
    # =========================================================

    def update_packet(
        self,
        source_ip: str,
        destination_ip: str,
        protocol: str,
        size: int = 0,
        direction: str = "",
        source_port: Optional[int] = None,
        destination_port: Optional[int] = None,
    ) -> None:

        self.packet_count += 1

        self.total_bytes += int(size or 0)

        protocol = str(
            protocol or "UNKNOWN"
        ).upper()

        self.protocol_counts[
            protocol
        ] += 1

        self.recent_packets.append(
            {
                "source": source_ip,
                "destination": destination_ip,
                "protocol": protocol,
                "size": int(size or 0),
                "direction": direction,
                "source_port": source_port,
                "destination_port": destination_port,
            }
        )

    # =========================================================
    # ALERT
    # =========================================================

    def update_alert(
        self,
        alert: Dict[str, Any],
    ) -> None:

        self.alert_count += 1

        severity = str(
            alert.get(
                "severity",
                "LOW"
            )
        ).upper()

        rule_id = str(
            alert.get(
                "rule_id",
                "UNKNOWN"
            )
        )

        self.severity_counts[
            severity
        ] += 1

        self.rule_counts[
            rule_id
        ] += 1

        self.recent_alerts.append(
            alert
        )

        suppressed = int(
            alert.get(
                "suppressed_count",
                0
            ) or 0
        )

        self.suppressed_count += suppressed

    # =========================================================
    # SUPPRESSION
    # =========================================================

    def update_suppression(
        self,
        count: int,
    ) -> None:

        self.suppressed_count += int(
            count or 0
        )

    # =========================================================
    # FLOW
    # =========================================================

    def update_flow_count(
        self,
        count: int,
    ) -> None:

        self.flow_count = int(
            count or 0
        )

    # =========================================================
    # RISK
    # =========================================================

    def update_risk(
        self,
        risk: Any,
    ) -> None:

        if risk is None:
            return

        if isinstance(risk, dict):

            score = risk.get(
                "score",
                risk.get(
                    "risk_score",
                    0
                )
            )

        else:

            score = getattr(
                risk,
                "score",
                getattr(
                    risk,
                    "risk_score",
                    0
                )
            )

        try:

            self.risk_score = max(
                self.risk_score,
                int(score)
            )

        except (
            TypeError,
            ValueError,
        ):

            pass

    # =========================================================
    # INCIDENT
    # =========================================================

    def update_incident(
        self,
        incident: Any,
    ) -> None:

        if incident is None:
            return

        if isinstance(
            incident,
            dict
        ):

            data = incident

        else:

            data = incident.to_dict()

        incident_id = data.get(
            "incident_id",
            "UNKNOWN"
        )

        severity = str(
            data.get(
                "severity",
                "LOW"
            )
        ).upper()

        status = str(
            data.get(
                "status",
                "OPEN"
            )
        ).upper()

        risk_score = int(
            data.get(
                "risk_score",
                0
            ) or 0
        )

        self.incident_count = max(
            self.incident_count,
            len(
                self.recent_incidents
            )
        )

        self.risk_score = max(
            self.risk_score,
            risk_score
        )

        self.recent_incidents.append(
            data
        )

        # Recalculate severity counters
        self._recalculate_incidents()

        # Timeline
        timeline = data.get(
            "timeline",
            []
        )

        if timeline:

            self.timeline_events.clear()

            for event in timeline[-10:]:

                self.timeline_events.append(
                    event
                )

    # =========================================================
    # INCIDENT SUMMARY
    # =========================================================

    def update_incident_summary(
        self,
        summary: Dict[str, Any],
    ) -> None:

        if not summary:
            return

        self.incident_count = int(
            summary.get(
                "total_incidents",
                self.incident_count
            )
        )

        self.active_incidents = int(
            summary.get(
                "active_incidents",
                self.active_incidents
            )
        )

        severity_counts = summary.get(
            "severity_counts",
            {}
        )

        self.critical_incidents = int(
            severity_counts.get(
                "CRITICAL",
                0
            )
        )

        self.high_incidents = int(
            severity_counts.get(
                "HIGH",
                0
            )
        )

        self.medium_incidents = int(
            severity_counts.get(
                "MEDIUM",
                0
            )
        )

        self.low_incidents = int(
            severity_counts.get(
                "LOW",
                0
            )
        )

    def _recalculate_incidents(
        self,
    ) -> None:

        self.critical_incidents = 0
        self.high_incidents = 0
        self.medium_incidents = 0
        self.low_incidents = 0

        self.active_incidents = 0

        for incident in self.recent_incidents:

            severity = str(
                incident.get(
                    "severity",
                    "LOW"
                )
            ).upper()

            status = str(
                incident.get(
                    "status",
                    "OPEN"
                )
            ).upper()

            if status != "RESOLVED":

                self.active_incidents += 1

            if severity == "CRITICAL":
                self.critical_incidents += 1

            elif severity == "HIGH":
                self.high_incidents += 1

            elif severity == "MEDIUM":
                self.medium_incidents += 1

            else:
                self.low_incidents += 1

    # =========================================================
    # PROFILE
    # =========================================================

    def update_profiles(
        self,
        attackers: Optional[List[Any]] = None,
        victims: Optional[List[Any]] = None,
    ) -> None:

        self.attackers = (
            attackers or []
        )

        self.victims = (
            victims or []
        )

    # =========================================================
    # TIMELINE
    # =========================================================

    def update_timeline(
        self,
        events: List[Any],
    ) -> None:

        self.timeline_events.clear()

        for event in events[-10:]:

            if hasattr(
                event,
                "to_dict"
            ):

                event = event.to_dict()

            self.timeline_events.append(
                event
            )

    # =========================================================
    # FORMATTING
    # =========================================================

    @staticmethod
    def _severity_text(
        severity: str,
    ) -> Text:

        severity = str(
            severity
        ).upper()

        text = Text(
            severity
        )

        if severity == "CRITICAL":

            text.stylize(
                "bold red"
            )

        elif severity == "HIGH":

            text.stylize(
                "bold yellow"
            )

        elif severity == "MEDIUM":

            text.stylize(
                "bold cyan"
            )

        else:

            text.stylize(
                "green"
            )

        return text

    # =========================================================
    # HEADER
    # =========================================================

    def render_header(self):

        title = Text(
            "NETSCOPE SOC",
            justify="center",
        )

        title.stylize(
            "bold"
        )

        subtitle = Text(
            "Security Operations Center",
            justify="center",
        )

        return Panel(
            Group(
                title,
                subtitle
            ),
            border_style="bright_blue",
        )

    # =========================================================
    # NETWORK STATS
    # =========================================================

    def render_network_stats(self):

        table = Table(
            expand=True
        )

        table.add_column(
            "Packets"
        )

        table.add_column(
            "Bytes"
        )

        table.add_column(
            "Flows"
        )

        table.add_column(
            "Protocols"
        )

        table.add_row(
            str(
                self.packet_count
            ),

            f"{self.total_bytes:,}",

            str(
                self.flow_count
            ),

            str(
                len(
                    self.protocol_counts
                )
            ),
        )

        return Panel(
            table,
            title="NETWORK",
        )

    # =========================================================
    # SOC SECURITY CENTER
    # =========================================================

    def render_security_center(self):

        table = Table(
            expand=True
        )

        table.add_column(
            "Metric"
        )

        table.add_column(
            "Value"
        )

        table.add_row(
            "Total Alerts",
            str(
                self.alert_count
            )
        )

        table.add_row(
            "Suppressed",
            str(
                self.suppressed_count
            )
        )

        table.add_row(
            "Critical Alerts",
            str(
                self.severity_counts.get(
                    "CRITICAL",
                    0
                )
            )
        )

        table.add_row(
            "High Alerts",
            str(
                self.severity_counts.get(
                    "HIGH",
                    0
                )
            )
        )

        table.add_row(
            "Risk Score",
            str(
                self.risk_score
            )
        )

        return Panel(
            table,
            title="SECURITY CENTER",
        )

    # =========================================================
    # INCIDENT CENTER
    # =========================================================

    def render_incident_center(self):

        table = Table(
            expand=True
        )

        table.add_column(
            "Metric"
        )

        table.add_column(
            "Count"
        )

        table.add_row(
            "Total Incidents",
            str(
                self.incident_count
            )
        )

        table.add_row(
            "Active",
            str(
                self.active_incidents
            )
        )

        table.add_row(
            "Critical",
            str(
                self.critical_incidents
            )
        )

        table.add_row(
            "High",
            str(
                self.high_incidents
            )
        )

        table.add_row(
            "Medium",
            str(
                self.medium_incidents
            )
        )

        return Panel(
            table,
            title="INCIDENT CENTER",
        )

    # =========================================================
    # TOP ATTACKERS
    # =========================================================

    def render_attackers(self):

        table = Table(
            expand=True
        )

        table.add_column(
            "IP"
        )

        table.add_column(
            "Risk"
        )

        table.add_column(
            "Severity"
        )

        table.add_column(
            "Alerts"
        )

        for attacker in self.attackers[:5]:

            if hasattr(
                attacker,
                "to_dict"
            ):

                attacker = attacker.to_dict()

            table.add_row(
                str(
                    attacker.get(
                        "ip",
                        "UNKNOWN"
                    )
                ),

                str(
                    attacker.get(
                        "risk_score",
                        0
                    )
                ),

                str(
                    attacker.get(
                        "severity",
                        "LOW"
                    )
                ),

                str(
                    attacker.get(
                        "alert_count",
                        0
                    )
                ),
            )

        if not self.attackers:

            table.add_row(
                "No attacker data",
                "-",
                "-",
                "-",
            )

        return Panel(
            table,
            title="TOP ATTACKERS",
        )

    # =========================================================
    # TOP VICTIMS
    # =========================================================

    def render_victims(self):

        table = Table(
            expand=True
        )

        table.add_column(
            "IP"
        )

        table.add_column(
            "Risk"
        )

        table.add_column(
            "Severity"
        )

        table.add_column(
            "Attacks"
        )

        for victim in self.victims[:5]:

            if hasattr(
                victim,
                "to_dict"
            ):

                victim = victim.to_dict()

            table.add_row(
                str(
                    victim.get(
                        "ip",
                        "UNKNOWN"
                    )
                ),

                str(
                    victim.get(
                        "risk_score",
                        0
                    )
                ),

                str(
                    victim.get(
                        "severity",
                        "LOW"
                    )
                ),

                str(
                    victim.get(
                        "attack_count",
                        0
                    )
                ),
            )

        if not self.victims:

            table.add_row(
                "No victim data",
                "-",
                "-",
                "-",
            )

        return Panel(
            table,
            title="TOP VICTIMS",
        )

    # =========================================================
    # ALERT HISTORY
    # =========================================================

    def render_alert_history(self):

        table = Table(
            expand=True
        )

        table.add_column(
            "Rule"
        )

        table.add_column(
            "Source"
        )

        table.add_column(
            "Destination"
        )

        table.add_column(
            "Severity"
        )

        for alert in list(
            self.recent_alerts
        )[-8:]:

            table.add_row(
                str(
                    alert.get(
                        "rule_id",
                        "UNKNOWN"
                    )
                ),

                str(
                    alert.get(
                        "source_ip",
                        "-"
                    )
                ),

                str(
                    alert.get(
                        "destination_ip",
                        "-"
                    )
                ),

                self._severity_text(
                    alert.get(
                        "severity",
                        "LOW"
                    )
                ),
            )

        if not self.recent_alerts:

            table.add_row(
                "No alerts",
                "-",
                "-",
                "-",
            )

        return Panel(
            table,
            title="ALERT HISTORY",
        )

    # =========================================================
    # INCIDENT HISTORY
    # =========================================================

    def render_incident_history(self):

        table = Table(
            expand=True
        )

        table.add_column(
            "Incident"
        )

        table.add_column(
            "Source"
        )

        table.add_column(
            "Target"
        )

        table.add_column(
            "Risk"
        )

        table.add_column(
            "Severity"
        )

        table.add_column(
            "Status"
        )

        for incident in list(
            self.recent_incidents
        )[-6:]:

            table.add_row(
                str(
                    incident.get(
                        "incident_id",
                        "-"
                    )
                ),

                str(
                    incident.get(
                        "source_ip",
                        "-"
                    )
                ),

                str(
                    incident.get(
                        "destination_ip",
                        "-"
                    )
                ),

                str(
                    incident.get(
                        "risk_score",
                        0
                    )
                ),

                self._severity_text(
                    incident.get(
                        "severity",
                        "LOW"
                    )
                ),

                str(
                    incident.get(
                        "status",
                        "OPEN"
                    )
                ),
            )

        if not self.recent_incidents:

            table.add_row(
                "No incidents",
                "-",
                "-",
                "-",
                "-",
                "-",
            )

        return Panel(
            table,
            title="INCIDENT HISTORY",
        )

    # =========================================================
    # ATTACK TIMELINE
    # =========================================================

    def render_timeline(self):

        table = Table(
            expand=True
        )

        table.add_column(
            "Time"
        )

        table.add_column(
            "Event"
        )

        table.add_column(
            "Alert"
        )

        for event in list(
            self.timeline_events
        )[-8:]:

            table.add_row(
                str(
                    event.get(
                        "timestamp",
                        "-"
                    )
                )[-8:],

                str(
                    event.get(
                        "event",
                        event.get(
                            "event_type",
                            "-"
                        )
                    )
                ),

                str(
                    event.get(
                        "alert_type",
                        event.get(
                            "rule_id",
                            "-"
                        )
                    )
                ),
            )

        if not self.timeline_events:

            table.add_row(
                "-",
                "No timeline events",
                "-",
            )

        return Panel(
            table,
            title="ATTACK TIMELINE",
        )

    # =========================================================
    # PROTOCOLS
    # =========================================================

    def render_protocols(self):

        table = Table(
            expand=True
        )

        table.add_column(
            "Protocol"
        )

        table.add_column(
            "Packets"
        )

        for protocol, count in (
            self.protocol_counts.most_common(6)
        ):

            table.add_row(
                protocol,
                str(count)
            )

        if not self.protocol_counts:

            table.add_row(
                "No traffic",
                "0"
            )

        return Panel(
            table,
            title="PROTOCOLS",
        )

    # =========================================================
    # RECENT PACKETS
    # =========================================================

    def render_packets(self):

        table = Table(
            expand=True
        )

        table.add_column(
            "Source"
        )

        table.add_column(
            "Destination"
        )

        table.add_column(
            "Protocol"
        )

        table.add_column(
            "Size"
        )

        for packet in list(
            self.recent_packets
        )[-8:]:

            table.add_row(
                str(
                    packet["source"]
                ),

                str(
                    packet["destination"]
                ),

                str(
                    packet["protocol"]
                ),

                str(
                    packet["size"]
                ),
            )

        if not self.recent_packets:

            table.add_row(
                "-",
                "-",
                "-",
                "0",
            )

        return Panel(
            table,
            title="RECENT PACKETS",
        )

    # =========================================================
    # MAIN RENDER
    # =========================================================

    def render(self):

        top = Table.grid(
            expand=True
        )

        top.add_column()
        top.add_column()

        top.add_row(
            self.render_network_stats(),
            self.render_security_center(),
        )

        soc = Table.grid(
            expand=True
        )

        soc.add_column()
        soc.add_column()

        soc.add_row(
            self.render_incident_center(),
            self.render_attackers(),
        )

        targets = Table.grid(
            expand=True
        )

        targets.add_column()
        targets.add_column()

        targets.add_row(
            self.render_victims(),
            self.render_protocols(),
        )

        return Group(
            self.render_header(),
            top,
            soc,
            targets,
            self.render_incident_history(),
            self.render_timeline(),
            self.render_alert_history(),
            self.render_packets(),
        )

    # =========================================================
    # LIVE
    # =========================================================

    @contextmanager
    def live(
        self,
        refresh_per_second: int = 4,
    ):

        with Live(
            self.render(),
            refresh_per_second=refresh_per_second,
            screen=False,
            transient=False,
        ) as live:

            self._live = live

            try:

                yield live

            finally:

                self._live = None

    # =========================================================
    # REFRESH
    # =========================================================

    def refresh(self):

        if getattr(
            self,
            "_live",
            None
        ):

            self._live.update(
                self.render()
            )