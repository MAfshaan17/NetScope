from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any


# ============================================================
# SECURITY ALERT
# ============================================================

@dataclass
class SecurityAlert:
    alert_type: str
    severity: str
    source_ip: str
    destination_ip: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    rule_id: str = "UNKNOWN"
    confidence: Any = "MEDIUM"
    timestamp: str = field(
        default_factory=lambda: datetime.now().isoformat(
            timespec="seconds"
        )
    )
    alert_id: str = ""
    status: str = "OPEN"
    suppressed_count: int = 0

    def to_dict(self):
        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "description": self.description,
            "evidence": self.evidence,
            "rule_id": self.rule_id,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "status": self.status,
            "suppressed_count": self.suppressed_count,
        }


# ============================================================
# SECURITY DETECTOR
# ============================================================

class SecurityDetector:

    def __init__(self):

        # ----------------------------------------------------
        # Legacy tracking
        # ----------------------------------------------------

        self.port_activity = defaultdict(set)
        self.syn_attempts = defaultdict(set)
        self.syn_responses = set()
        self.packet_counts = defaultdict(int)

        # ----------------------------------------------------
        # Alerts
        # ----------------------------------------------------

        self.alerts = []

        # ----------------------------------------------------
        # V1.4 time windows
        # ----------------------------------------------------

        self.port_events = defaultdict(deque)
        self.syn_events = defaultdict(deque)

        self.detection_window = timedelta(seconds=5)

        # ----------------------------------------------------
        # V1.4 cooldown
        # ----------------------------------------------------

        self.alert_cooldown = timedelta(seconds=60)
        self.last_alert_time = {}

        self.suppressed_alerts = defaultdict(int)

        # ----------------------------------------------------
        # Alert bookkeeping
        # ----------------------------------------------------

        self.alert_keys = set()
        self.alert_counter = 0

    # ========================================================
    # ALERT ID
    # ========================================================

    def _generate_alert_id(self):

        self.alert_counter += 1

        return (
            f"NS-{datetime.now().strftime('%Y%m%d')}-"
            f"{self.alert_counter:04d}"
        )

    # ========================================================
    # BROADCAST / MULTICAST
    # ========================================================

    def _is_broadcast(self, ip):

        if not ip:
            return True

        if ip == "255.255.255.255":
            return True

        try:
            if int(ip.split(".")[-1]) == 255:
                return True
        except (ValueError, IndexError):
            pass

        return False

    def _is_multicast(self, ip):

        if not ip:
            return False

        try:
            first_octet = int(ip.split(".")[0])

            return 224 <= first_octet <= 239

        except (ValueError, IndexError):
            return False

    def _ignored_destination(self, destination_ip):

        return (
            self._is_broadcast(destination_ip)
            or self._is_multicast(destination_ip)
        )

    # ========================================================
    # TIME WINDOW
    # ========================================================

    def remove_old_events(self, events, now):

        while events:

            timestamp = events[0][0]

            if now - timestamp > self.detection_window:
                events.popleft()

            else:
                break

    # ========================================================
    # SEVERITY
    # ========================================================

    def calculate_port_scan_severity(self, unique_ports):

        if unique_ports >= 50:
            return "CRITICAL"

        if unique_ports >= 20:
            return "HIGH"

        if unique_ports >= 10:
            return "MEDIUM"

        if unique_ports >= 5:
            return "LOW"

        return None

    def calculate_syn_scan_severity(self, count):

        if count >= 50:
            return "CRITICAL"

        if count >= 20:
            return "HIGH"

        if count >= 10:
            return "MEDIUM"

        if count >= 5:
            return "LOW"

        return None

    # ========================================================
    # CONFIDENCE
    # ========================================================

    def calculate_confidence(self, count):

        if count >= 20:
            return "HIGH"

        if count >= 10:
            return "MEDIUM"

        return "LOW"

    # ========================================================
    # COOLDOWN
    # ========================================================

    def is_alert_on_cooldown(self, alert_key, now):

        last_time = self.last_alert_time.get(alert_key)

        if last_time is None:
            return False

        return (
            now - last_time
        ) < self.alert_cooldown

    def mark_alert_generated(self, alert_key, now):

        self.last_alert_time[alert_key] = now

    # ========================================================
    # FIND ALERT
    # ========================================================

    def find_alert(
        self,
        rule_id,
        source_ip,
        destination_ip
    ):

        for alert in reversed(self.alerts):

            if (
                alert.rule_id == rule_id
                and alert.source_ip == source_ip
                and alert.destination_ip == destination_ip
            ):
                return alert

        return None

    # ========================================================
    # CREATE ALERT
    # ========================================================

    def create_alert(
        self,
        alert_type,
        severity,
        source_ip,
        destination_ip,
        description,
        evidence=None,
        rule_id="UNKNOWN",
        confidence="MEDIUM"
    ):

        names = {
            "PORT_SCAN": "Possible Port Scan",
            "SYN_SCAN": "Possible SYN Scan",
            "HIGH_ACTIVITY": "High Network Activity",
        }

        display_type = names.get(
            alert_type,
            alert_type
        )

        alert = SecurityAlert(
            alert_type=display_type,
            severity=severity,
            source_ip=source_ip,
            destination_ip=destination_ip,
            description=description,
            evidence=evidence or {},
            rule_id=rule_id,
            confidence=confidence,
            alert_id=self._generate_alert_id(),
        )

        self.alerts.append(alert)

        return alert.to_dict()

    # ========================================================
    # SEVERITY RANK
    # ========================================================

    def _severity_rank(self, severity):

        return {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }.get(severity, 0)

    # ========================================================
    # V1.4 PORT SCAN
    # ========================================================

    def detect_port_scan(
        self,
        source_ip,
        destination_ip,
        destination_port,
        protocol="TCP"
    ):

        if self._ignored_destination(destination_ip):
            return None

        now = datetime.now()

        key = (
            source_ip,
            destination_ip,
            protocol
        )

        self.port_events[key].append(
            (
                now,
                destination_port
            )
        )

        self.remove_old_events(
            self.port_events[key],
            now
        )

        unique_ports = {
            port
            for _, port in self.port_events[key]
        }

        count = len(unique_ports)

        severity = self.calculate_port_scan_severity(
            count
        )

        if severity is None:
            return None

        confidence = self.calculate_confidence(
            count
        )

        alert_key = (
            "PORT_SCAN",
            source_ip,
            destination_ip,
            protocol
        )

        existing_alert = self.find_alert(
            "NS-1001",
            source_ip,
            destination_ip
        )

        # ----------------------------------------------------
        # COOLDOWN
        # ----------------------------------------------------

        if self.is_alert_on_cooldown(
            alert_key,
            now
        ):

            if existing_alert is not None:

                old_rank = self._severity_rank(
                    existing_alert.severity
                )

                new_rank = self._severity_rank(
                    severity
                )

                # Severity escalation
                if new_rank > old_rank:

                    alert = self.create_alert(
                        "PORT_SCAN",
                        severity,
                        source_ip,
                        destination_ip,
                        (
                            "Port scan severity escalated "
                            f"to {severity}"
                        ),
                        evidence={
                            "unique_ports": count,
                            "ports": sorted(unique_ports),
                            "protocol": protocol,
                            "time_window_seconds": 5,
                        },
                        rule_id="NS-1001",
                        confidence=confidence
                    )

                    self.mark_alert_generated(
                        alert_key,
                        now
                    )

                    return {
                        **alert,
                        "alert_type": "PORT_SCAN"
                    }

            # Duplicate suppressed
            self.suppressed_alerts[
                alert_key
            ] += 1

            if existing_alert is not None:

                existing_alert.suppressed_count = (
                    self.suppressed_alerts[
                        alert_key
                    ]
                )

            return None

        # ----------------------------------------------------
        # NEW ALERT
        # ----------------------------------------------------

        alert = self.create_alert(
            "PORT_SCAN",
            severity,
            source_ip,
            destination_ip,
            (
                "Possible port scan detected: "
                f"{count} unique ports contacted "
                "within 5 seconds"
            ),
            evidence={
                "unique_ports": count,
                "ports": sorted(unique_ports),
                "protocol": protocol,
                "time_window_seconds": 5,
            },
            rule_id="NS-1001",
            confidence=confidence
        )

        self.mark_alert_generated(
            alert_key,
            now
        )

        self.alert_keys.add(
            alert_key
        )

        return {
            **alert,
            "alert_type": "PORT_SCAN"
        }

    # ========================================================
    # LEGACY PORT SCAN
    # ========================================================

    def detect_port_scans(self, threshold=10):

        detected = []

        for key, ports in self.port_activity.items():

            source_ip, destination_ip, protocol = key

            if self._ignored_destination(
                destination_ip
            ):
                continue

            if len(ports) < threshold:
                continue

            # ------------------------------------------------
            # Convert matching V1.4 alerts
            # ------------------------------------------------

            matching_alerts = []

            for alert in self.alerts:

                if (
                    alert.alert_type == "Possible Port Scan"
                    and alert.source_ip == source_ip
                    and alert.destination_ip == destination_ip
                ):

                    matching_alerts.append(alert)

            if matching_alerts:

                for existing in matching_alerts:

                    existing.rule_id = "NET-PORT-001"
                    existing.severity = "HIGH"
                    existing.confidence = "HIGH"

                    existing.evidence.update({
                        "unique_ports": len(ports),
                        "ports": sorted(ports),
                        "protocol": protocol,
                    })

                result = matching_alerts[0].to_dict()
                result["alert_type"] = "PORT_SCAN"

                detected.append(result)

                continue

            # ------------------------------------------------
            # Create legacy alert
            # ------------------------------------------------

            alert = self.create_alert(
                "PORT_SCAN",
                "HIGH",
                source_ip,
                destination_ip,
                (
                    "Possible port scan detected: "
                    f"{len(ports)} unique ports"
                ),
                evidence={
                    "unique_ports": len(ports),
                    "ports": sorted(ports),
                    "protocol": protocol,
                },
                rule_id="NET-PORT-001",
                confidence="HIGH"
            )

            result = {
                **alert,
                "alert_type": "PORT_SCAN"
            }

            detected.append(result)

        return detected

    # ========================================================
    # V1.4 SYN SCAN
    # ========================================================

    def detect_syn_scan(
        self,
        source_ip,
        destination_ip,
        destination_port,
        flags
    ):

        flag_string = str(flags).upper()

        # Must contain SYN
        if "S" not in flag_string:
            return None

        # SYN-ACK is not a scan attempt
        if "A" in flag_string:
            return None

        if self._ignored_destination(
            destination_ip
        ):
            return None

        now = datetime.now()

        key = (
            source_ip,
            destination_ip
        )

        self.syn_events[key].append(
            (
                now,
                destination_port
            )
        )

        self.remove_old_events(
            self.syn_events[key],
            now
        )

        unique_ports = {
            port
            for _, port in self.syn_events[key]
        }

        syn_packets = len(
            self.syn_events[key]
        )

        count = len(unique_ports)

        severity = self.calculate_syn_scan_severity(
            count
        )

        if severity is None:
            return None

        confidence = self.calculate_confidence(
            count
        )

        alert_key = (
            "SYN_SCAN",
            source_ip,
            destination_ip
        )

        existing_alert = self.find_alert(
            "NS-1002",
            source_ip,
            destination_ip
        )

        # ----------------------------------------------------
        # COOLDOWN
        # ----------------------------------------------------

        if self.is_alert_on_cooldown(
            alert_key,
            now
        ):

            if existing_alert is not None:

                old_rank = self._severity_rank(
                    existing_alert.severity
                )

                new_rank = self._severity_rank(
                    severity
                )

                if new_rank > old_rank:

                    alert = self.create_alert(
                        "SYN_SCAN",
                        severity,
                        source_ip,
                        destination_ip,
                        (
                            "SYN scan severity escalated "
                            f"to {severity}"
                        ),
                        evidence={
                            "unique_ports": count,
                            "syn_packets": syn_packets,
                            "ports": sorted(unique_ports),
                            "time_window_seconds": 5,
                        },
                        rule_id="NS-1002",
                        confidence=confidence
                    )

                    self.mark_alert_generated(
                        alert_key,
                        now
                    )

                    return {
                        **alert,
                        "alert_type": "SYN_SCAN"
                    }

            self.suppressed_alerts[
                alert_key
            ] += 1

            if existing_alert is not None:

                existing_alert.suppressed_count = (
                    self.suppressed_alerts[
                        alert_key
                    ]
                )

            return None

        # ----------------------------------------------------
        # NEW SYN ALERT
        # ----------------------------------------------------

        alert = self.create_alert(
            "SYN_SCAN",
            severity,
            source_ip,
            destination_ip,
            (
                "Possible SYN scan detected: "
                f"{syn_packets} SYN packets "
                "within 5 seconds"
            ),
            evidence={
                "unique_ports": count,
                "syn_packets": syn_packets,
                "ports": sorted(unique_ports),
                "time_window_seconds": 5,
            },
            rule_id="NS-1002",
            confidence=confidence
        )

        self.mark_alert_generated(
            alert_key,
            now
        )

        self.alert_keys.add(
            alert_key
        )

        return {
            **alert,
            "alert_type": "SYN_SCAN"
        }

    # ========================================================
    # LEGACY SYN SCAN
    # ========================================================

    def detect_syn_scans(self, threshold=10):

        detected = []

        for key, ports in self.syn_attempts.items():

            source_ip, destination_ip = key

            if self._ignored_destination(
                destination_ip
            ):
                continue

            if len(ports) < threshold:
                continue

            existing = self.find_alert(
                "NS-1002",
                source_ip,
                destination_ip
            )

            if existing is not None:

                existing.severity = "HIGH"
                existing.confidence = "HIGH"

                existing.evidence.update({
                    "unique_ports": len(ports),
                    "ports": sorted(ports),
                })

                result = existing.to_dict()
                result["alert_type"] = "SYN_SCAN"

                detected.append(result)

                continue

            alert = self.create_alert(
                "SYN_SCAN",
                "HIGH",
                source_ip,
                destination_ip,
                (
                    "Possible SYN scan detected: "
                    f"{len(ports)} unique ports"
                ),
                evidence={
                    "unique_ports": len(ports),
                    "ports": sorted(ports),
                },
                rule_id="NS-1002",
                confidence="HIGH"
            )

            result = {
                **alert,
                "alert_type": "SYN_SCAN"
            }

            detected.append(result)

        return detected

    # ========================================================
    # HIGH ACTIVITY
    # ========================================================

    def detect_high_activity(self, threshold=100):

        detected = []

        for source_ip, count in self.packet_counts.items():

            if count < threshold:
                continue

            alert_key = (
                "HIGH_ACTIVITY",
                source_ip
            )

            now = datetime.now()

            existing = self.find_alert(
                "NS-1003",
                source_ip,
                "N/A"
            )

            # ------------------------------------------------
            # COOLDOWN / DUPLICATE SUPPRESSION
            # ------------------------------------------------

            if self.is_alert_on_cooldown(
                alert_key,
                now
            ):

                self.suppressed_alerts[
                    alert_key
                ] += 1

                if existing is not None:

                    existing.suppressed_count = (
                        self.suppressed_alerts[
                            alert_key
                        ]
                    )

                continue

            # ------------------------------------------------
            # CREATE ALERT
            # ------------------------------------------------

            alert = self.create_alert(
                "HIGH_ACTIVITY",
                "MEDIUM",
                source_ip,
                "N/A",
                (
                    "High network activity detected: "
                    f"{count} packets"
                ),
                evidence={
                    "packet_count": count,
                    "threshold": threshold,
                },
                rule_id="NS-1003",
                confidence="MEDIUM"
            )

            self.mark_alert_generated(
                alert_key,
                now
            )

            result = {
                **alert,
                "alert_type": "HIGH_ACTIVITY"
            }

            detected.append(result)

        return detected

    # ========================================================
    # V1.5 REAL-TIME HIGH ACTIVITY
    # ========================================================

    def detect_high_activity_realtime(
        self,
        source_ip,
        threshold=100
    ):

        count = self.packet_counts.get(
            source_ip,
            0
        )

        if count < threshold:
            return None

        alert_key = (
            "HIGH_ACTIVITY",
            source_ip
        )

        now = datetime.now()

        existing = self.find_alert(
            "NS-1003",
            source_ip,
            "N/A"
        )

        # ----------------------------------------------------
        # COOLDOWN
        # ----------------------------------------------------

        if self.is_alert_on_cooldown(
            alert_key,
            now
        ):

            self.suppressed_alerts[
                alert_key
            ] += 1

            if existing is not None:

                existing.suppressed_count = (
                    self.suppressed_alerts[
                        alert_key
                    ]
                )

            return None

        # ----------------------------------------------------
        # NEW REAL-TIME ALERT
        # ----------------------------------------------------

        alert = self.create_alert(
            "HIGH_ACTIVITY",
            "MEDIUM",
            source_ip,
            "N/A",
            (
                "High network activity detected "
                "in real time: "
                f"{count} packets"
            ),
            evidence={
                "packet_count": count,
                "threshold": threshold,
                "detection_mode": "REAL_TIME",
            },
            rule_id="NS-1003",
            confidence="MEDIUM"
        )

        self.mark_alert_generated(
            alert_key,
            now
        )

        self.alert_keys.add(
            alert_key
        )

        return {
            **alert,
            "alert_type": "HIGH_ACTIVITY"
        }

    # ========================================================
    # PACKET INSPECTION
    # ========================================================

    def inspect_packet(
        self,
        source_ip,
        destination_ip,
        source_port=None,
        destination_port=None,
        protocol="TCP",
        direction=None,
        tcp_flags=None,
        flags=None
    ):

        # ----------------------------------------------------
        # Support both tcp_flags and flags
        # ----------------------------------------------------

        if tcp_flags is not None:
            packet_flags = tcp_flags
        else:
            packet_flags = flags or ""

        flag_string = str(
            packet_flags
        ).upper()

        # ----------------------------------------------------
        # Ignore broadcast / multicast
        # ----------------------------------------------------

        if self._ignored_destination(
            destination_ip
        ):
            return []

        # ----------------------------------------------------
        # Packet count
        # ----------------------------------------------------

        self.packet_counts[
            source_ip
        ] += 1

        alerts = []

        # ----------------------------------------------------
        # V1.5 REAL-TIME HIGH ACTIVITY
        # ----------------------------------------------------

        activity_alert = (
            self.detect_high_activity_realtime(
                source_ip=source_ip,
                threshold=100
            )
        )

        if activity_alert is not None:
            alerts.append(
                activity_alert
            )

        # ----------------------------------------------------
        # Legacy port tracking
        # ----------------------------------------------------

        if destination_port is not None:

            key = (
                source_ip,
                destination_ip,
                protocol
            )

            self.port_activity[
                key
            ].add(
                destination_port
            )

        # ----------------------------------------------------
        # Legacy SYN tracking
        # ----------------------------------------------------

        is_syn = (
            "S" in flag_string
            and "A" not in flag_string
        )

        if (
            protocol.upper() == "TCP"
            and is_syn
            and destination_port is not None
        ):

            syn_key = (
                source_ip,
                destination_ip
            )

            self.syn_attempts[
                syn_key
            ].add(
                destination_port
            )

        # ----------------------------------------------------
        # V1.4 PORT SCAN
        # ----------------------------------------------------

        if destination_port is not None:

            port_alert = self.detect_port_scan(
                source_ip=source_ip,
                destination_ip=destination_ip,
                destination_port=destination_port,
                protocol=protocol
            )

            if port_alert is not None:
                alerts.append(
                    port_alert
                )

        # ----------------------------------------------------
        # V1.4 SYN SCAN
        # ----------------------------------------------------

        if (
            destination_port is not None
            and protocol.upper() == "TCP"
        ):

            normalized_flags = flag_string

            if normalized_flags == "SYN":
                normalized_flags = "S"

            elif normalized_flags == "ACK":
                normalized_flags = "A"

            elif normalized_flags in (
                "SYN-ACK",
                "SYNACK"
            ):
                normalized_flags = "SA"

            syn_alert = self.detect_syn_scan(
                source_ip=source_ip,
                destination_ip=destination_ip,
                destination_port=destination_port,
                flags=normalized_flags
            )

            if syn_alert is not None:
                alerts.append(
                    syn_alert
                )

        return alerts

    # ========================================================
    # DETECT ALL
    # ========================================================

    def detect_all(self):

        results = []

        results.extend(
            self.detect_port_scans()
        )

        results.extend(
            self.detect_syn_scans()
        )

        results.extend(
            self.detect_high_activity()
        )

        return results

    # ========================================================
    # DISPLAY ALERTS
    # ========================================================

    def display_alerts(self):

        if not self.alerts:

            print(
                "\nNo security alerts detected."
            )

            return

        print(
            "\n" + "=" * 70
        )

        print(
            "SECURITY ALERTS"
        )

        print(
            "=" * 70
        )

        for alert in self.alerts:

            print(
                f"\n[{alert.alert_id}] "
                f"{alert.alert_type}"
            )

            print(
                f"Severity   : {alert.severity}"
            )

            print(
                f"Confidence : {alert.confidence}"
            )

            print(
                f"Source     : {alert.source_ip}"
            )

            print(
                f"Destination: {alert.destination_ip}"
            )

            print(
                f"Rule       : {alert.rule_id}"
            )

            print(
                f"Status     : {alert.status}"
            )

            print(
                f"Suppressed : {alert.suppressed_count}"
            )

            print(
                f"Time       : {alert.timestamp}"
            )

            print(
                f"Description: {alert.description}"
            )

            print(
                "-" * 70
            )