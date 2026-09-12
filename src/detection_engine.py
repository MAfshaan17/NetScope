"""
NetScope V1.7.3
Advanced Detection Engine.

Rules:
    NS-1004 - DNS Request Burst
    NS-1005 - High Connection Rate
    NS-1007 - Traffic Burst
"""

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta


# ============================================================
# EVENT MODELS
# ============================================================

@dataclass
class ConnectionEvent:
    timestamp: datetime
    source_ip: str
    destination_ip: str
    destination_port: int | None
    protocol: str


@dataclass
class DNSEvent:
    timestamp: datetime
    source_ip: str
    destination_ip: str
    destination_port: int
    query_name: str | None


@dataclass
class TrafficEvent:
    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: str
    size: int


# ============================================================
# ALERT MODEL
# ============================================================

@dataclass
class DetectionAlert:

    alert_type: str
    severity: str

    source_ip: str
    destination_ip: str

    description: str

    rule_id: str
    confidence: str

    timestamp: str

    evidence: dict

    def to_dict(self):

        return {
            "alert_type": self.alert_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "description": self.description,
            "rule_id": self.rule_id,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "evidence": self.evidence,
        }


# ============================================================
# DETECTION ENGINE
# ============================================================

class DetectionEngine:

    def __init__(
        self,
        connection_threshold=20,
        dns_threshold=20,
        traffic_packet_threshold=100,
        traffic_byte_threshold=100000,
        detection_window_seconds=5,
        cooldown_seconds=60,
    ):

        # ----------------------------------------------------
        # Thresholds
        # ----------------------------------------------------

        self.connection_threshold = (
            connection_threshold
        )

        self.dns_threshold = (
            dns_threshold
        )

        self.traffic_packet_threshold = (
            traffic_packet_threshold
        )

        self.traffic_byte_threshold = (
            traffic_byte_threshold
        )

        # ----------------------------------------------------
        # Timing
        # ----------------------------------------------------

        self.detection_window = timedelta(
            seconds=detection_window_seconds
        )

        self.cooldown = timedelta(
            seconds=cooldown_seconds
        )

        # ----------------------------------------------------
        # Event history
        # ----------------------------------------------------

        self.connection_events = defaultdict(
            deque
        )

        self.dns_events = defaultdict(
            deque
        )

        self.traffic_events = defaultdict(
            deque
        )

        # ----------------------------------------------------
        # Alerts
        # ----------------------------------------------------

        self.alerts = []

        self.last_alert_time = {}

        self.suppressed_alerts = defaultdict(
            int
        )

    # ========================================================
    # EVENT CLEANUP
    # ========================================================

    def _remove_old_events(
        self,
        events,
        now
    ):

        cutoff = (
            now - self.detection_window
        )

        while events:

            if events[0].timestamp >= cutoff:
                break

            events.popleft()

    # ========================================================
    # COOLDOWN
    # ========================================================

    def _on_cooldown(
        self,
        key,
        now
    ):

        last_time = self.last_alert_time.get(
            key
        )

        if last_time is None:
            return False

        return (
            now - last_time
            < self.cooldown
        )

    # ========================================================
    # NS-1005
    # HIGH CONNECTION RATE
    # ========================================================

    def detect_connection_rate(
        self,
        source_ip,
        destination_ip,
        destination_port=None,
        protocol="TCP",
    ):

        now = datetime.now()

        key = (
            source_ip,
            destination_ip
        )

        event = ConnectionEvent(
            timestamp=now,
            source_ip=source_ip,
            destination_ip=destination_ip,
            destination_port=destination_port,
            protocol=protocol,
        )

        events = self.connection_events[key]

        events.append(event)

        self._remove_old_events(
            events,
            now
        )

        count = len(events)

        if count < self.connection_threshold:
            return None

        cooldown_key = (
            "NS-1005",
            source_ip,
            destination_ip
        )

        if self._on_cooldown(
            cooldown_key,
            now
        ):

            self.suppressed_alerts[
                cooldown_key
            ] += 1

            return None

        if count >= 100:
            severity = "CRITICAL"
            confidence = "HIGH"

        elif count >= 50:
            severity = "HIGH"
            confidence = "HIGH"

        elif count >= 30:
            severity = "MEDIUM"
            confidence = "HIGH"

        else:
            severity = "LOW"
            confidence = "MEDIUM"

        ports = sorted(
            {
                event.destination_port
                for event in events
                if event.destination_port is not None
            }
        )

        protocols = sorted(
            {
                event.protocol
                for event in events
            }
        )

        alert = DetectionAlert(
            alert_type="High Connection Rate",

            severity=severity,

            source_ip=source_ip,

            destination_ip=destination_ip,

            description=(
                f"High connection rate detected: "
                f"{count} connection events within "
                f"{self.detection_window.total_seconds():.0f} seconds"
            ),

            rule_id="NS-1005",

            confidence=confidence,

            timestamp=now.isoformat(),

            evidence={
                "connection_count": count,
                "threshold": self.connection_threshold,
                "time_window_seconds": (
                    self.detection_window.total_seconds()
                ),
                "ports": ports,
                "protocols": protocols,
            },
        )

        result = alert.to_dict()

        self.alerts.append(result)

        self.last_alert_time[
            cooldown_key
        ] = now

        return result

    # ========================================================
    # NS-1004
    # DNS REQUEST BURST
    # ========================================================

    def detect_dns_anomaly(
        self,
        source_ip,
        destination_ip,
        destination_port=53,
        query_name=None,
    ):

        now = datetime.now()

        if destination_port != 53:
            return None

        key = (
            source_ip,
            destination_ip
        )

        event = DNSEvent(
            timestamp=now,
            source_ip=source_ip,
            destination_ip=destination_ip,
            destination_port=destination_port,
            query_name=query_name,
        )

        events = self.dns_events[key]

        events.append(event)

        self._remove_old_events(
            events,
            now
        )

        count = len(events)

        if count < self.dns_threshold:
            return None

        cooldown_key = (
            "NS-1004",
            source_ip,
            destination_ip
        )

        if self._on_cooldown(
            cooldown_key,
            now
        ):

            self.suppressed_alerts[
                cooldown_key
            ] += 1

            return None

        if count >= 100:
            severity = "CRITICAL"
            confidence = "HIGH"

        elif count >= 50:
            severity = "HIGH"
            confidence = "HIGH"

        elif count >= 30:
            severity = "MEDIUM"
            confidence = "HIGH"

        else:
            severity = "LOW"
            confidence = "MEDIUM"

        query_names = sorted(
            {
                event.query_name
                for event in events
                if event.query_name
            }
        )

        alert = DetectionAlert(
            alert_type="DNS Request Burst",

            severity=severity,

            source_ip=source_ip,

            destination_ip=destination_ip,

            description=(
                f"Unusually high DNS activity detected: "
                f"{count} DNS requests within "
                f"{self.detection_window.total_seconds():.0f} seconds"
            ),

            rule_id="NS-1004",

            confidence=confidence,

            timestamp=now.isoformat(),

            evidence={
                "dns_request_count": count,
                "threshold": self.dns_threshold,
                "time_window_seconds": (
                    self.detection_window.total_seconds()
                ),
                "destination_port": destination_port,
                "unique_queries": len(query_names),
                "queries": query_names[:20],
            },
        )

        result = alert.to_dict()

        self.alerts.append(result)

        self.last_alert_time[
            cooldown_key
        ] = now

        return result

    # ========================================================
    # NS-1007
    # TRAFFIC BURST
    # ========================================================

    def detect_traffic_burst(
        self,
        source_ip,
        destination_ip,
        protocol="TCP",
        size=0,
    ):
        """
        Detect sudden packet/byte bursts.

        Rule:
            NS-1007

        Default thresholds:
            100 packets / 5 seconds
            OR
            100,000 bytes / 5 seconds
        """

        now = datetime.now()

        key = (
            source_ip,
            destination_ip
        )

        event = TrafficEvent(
            timestamp=now,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            size=max(int(size), 0),
        )

        events = self.traffic_events[key]

        events.append(event)

        self._remove_old_events(
            events,
            now
        )

        packet_count = len(events)

        total_bytes = sum(
            event.size
            for event in events
        )

        packet_trigger = (
            packet_count
            >= self.traffic_packet_threshold
        )

        byte_trigger = (
            total_bytes
            >= self.traffic_byte_threshold
        )

        if not packet_trigger and not byte_trigger:
            return None

        cooldown_key = (
            "NS-1007",
            source_ip,
            destination_ip
        )

        if self._on_cooldown(
            cooldown_key,
            now
        ):

            self.suppressed_alerts[
                cooldown_key
            ] += 1

            return None

        # ----------------------------------------------------
        # Severity
        # ----------------------------------------------------

        if (
            packet_count >= 500
            or total_bytes >= 1000000
        ):

            severity = "CRITICAL"
            confidence = "HIGH"

        elif (
            packet_count >= 250
            or total_bytes >= 500000
        ):

            severity = "HIGH"
            confidence = "HIGH"

        elif (
            packet_count >= 150
            or total_bytes >= 250000
        ):

            severity = "MEDIUM"
            confidence = "HIGH"

        else:

            severity = "LOW"
            confidence = "MEDIUM"

        # ----------------------------------------------------
        # Protocols
        # ----------------------------------------------------

        protocols = sorted(
            {
                event.protocol
                for event in events
            }
        )

        # ----------------------------------------------------
        # Alert
        # ----------------------------------------------------

        alert = DetectionAlert(

            alert_type="Traffic Burst",

            severity=severity,

            source_ip=source_ip,

            destination_ip=destination_ip,

            description=(
                f"Traffic burst detected: "
                f"{packet_count} packets / "
                f"{total_bytes} bytes within "
                f"{self.detection_window.total_seconds():.0f} seconds"
            ),

            rule_id="NS-1007",

            confidence=confidence,

            timestamp=now.isoformat(),

            evidence={
                "packet_count": packet_count,
                "total_bytes": total_bytes,
                "packet_threshold": (
                    self.traffic_packet_threshold
                ),
                "byte_threshold": (
                    self.traffic_byte_threshold
                ),
                "time_window_seconds": (
                    self.detection_window.total_seconds()
                ),
                "packet_threshold_triggered": (
                    packet_trigger
                ),
                "byte_threshold_triggered": (
                    byte_trigger
                ),
                "protocols": protocols,
            },
        )

        result = alert.to_dict()

        self.alerts.append(result)

        self.last_alert_time[
            cooldown_key
        ] = now

        return result

    # ========================================================
    # PACKET INSPECTION
    # ========================================================

    def inspect_packet(
        self,
        source_ip,
        destination_ip,
        destination_port=None,
        protocol="TCP",
        query_name=None,
        size=0,
    ):

        alerts = []

        protocol = str(
            protocol
        ).upper()

        # ----------------------------------------------------
        # DNS
        # ----------------------------------------------------

        if (
            protocol == "UDP"
            and destination_port == 53
        ):

            alert = self.detect_dns_anomaly(

                source_ip=source_ip,

                destination_ip=destination_ip,

                destination_port=destination_port,

                query_name=query_name,
            )

            if alert is not None:
                alerts.append(alert)

        # ----------------------------------------------------
        # Connection rate
        # ----------------------------------------------------

        alert = self.detect_connection_rate(

            source_ip=source_ip,

            destination_ip=destination_ip,

            destination_port=destination_port,

            protocol=protocol,
        )

        if alert is not None:
            alerts.append(alert)

        # ----------------------------------------------------
        # Traffic burst
        # ----------------------------------------------------

        alert = self.detect_traffic_burst(

            source_ip=source_ip,

            destination_ip=destination_ip,

            protocol=protocol,

            size=size,
        )

        if alert is not None:
            alerts.append(alert)

        return alerts

    # ========================================================
    # RESET
    # ========================================================

    def reset(self):

        self.connection_events.clear()

        self.dns_events.clear()

        self.traffic_events.clear()

        self.alerts.clear()

        self.last_alert_time.clear()

        self.suppressed_alerts.clear()

    # ========================================================
    # SUMMARY
    # ========================================================

    def get_summary(self):

        return {
            "total_alerts": len(
                self.alerts
            ),

            "suppressed_alerts": sum(
                self.suppressed_alerts.values()
            ),

            "tracked_connections": len(
                self.connection_events
            ),

            "tracked_dns_sources": len(
                self.dns_events
            ),

            "tracked_traffic_flows": len(
                self.traffic_events
            ),
        }


# ============================================================
# MANUAL TEST
# ============================================================

if __name__ == "__main__":

    engine = DetectionEngine()

    print()

    print("=" * 60)

    print(
        "        NETSCOPE V1.7.3 DETECTION ENGINE"
    )

    print("=" * 60)

    # --------------------------------------------------------
    # DNS
    # --------------------------------------------------------

    print()

    print(
        "Testing NS-1004 DNS burst..."
    )

    dns_alerts = []

    for i in range(20):

        dns_alerts.extend(
            engine.inspect_packet(

                source_ip="10.0.0.10",

                destination_ip="8.8.8.8",

                destination_port=53,

                protocol="UDP",

                query_name=f"example{i}.com",

                size=100,
            )
        )

    for alert in dns_alerts:

        if alert["rule_id"] == "NS-1004":

            print(
                f"  {alert['rule_id']} "
                f"{alert['severity']} "
                f"{alert['alert_type']}"
            )

    # --------------------------------------------------------
    # Connection rate
    # --------------------------------------------------------

    print()

    print(
        "Testing NS-1005 connection rate..."
    )

    connection_alerts = []

    for port in range(20):

        connection_alerts.extend(
            engine.inspect_packet(

                source_ip="10.0.0.15",

                destination_ip="10.0.0.20",

                destination_port=1000 + port,

                protocol="TCP",

                size=500,
            )
        )

    for alert in connection_alerts:

        if alert["rule_id"] == "NS-1005":

            print(
                f"  {alert['rule_id']} "
                f"{alert['severity']} "
                f"{alert['alert_type']}"
            )

    # --------------------------------------------------------
    # Traffic burst
    # --------------------------------------------------------

    print()

    print(
        "Testing NS-1007 traffic burst..."
    )

    burst_alerts = []

    for _ in range(100):

        burst_alerts.extend(
            engine.inspect_packet(

                source_ip="10.0.0.30",

                destination_ip="10.0.0.40",

                destination_port=80,

                protocol="TCP",

                size=1000,
            )
        )

    for alert in burst_alerts:

        if alert["rule_id"] == "NS-1007":

            print(
                f"  {alert['rule_id']} "
                f"{alert['severity']} "
                f"{alert['alert_type']}"
            )

    print()

    print(
        f"Summary: {engine.get_summary()}"
    )

    print()