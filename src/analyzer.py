"""
NetScope Network Analyzer
V2.0

Live packet capture -> legacy detection -> modern detection ->
Threat Intelligence -> Risk -> SOC incidents -> timeline/profiles ->
dashboard -> persistent storage.

Run:
    python -m src.analyzer
"""

import argparse
from typing import Any

from scapy.all import sniff, IP, TCP, UDP

from .service_detector import identify_service
from .flag_decoder import decode_tcp_flags
from .statistics import TrafficStatistics
from .flow_tracker import FlowTracker
from .security_detector import SecurityDetector
from .detection_engine import DetectionEngine
from .risk_engine import RiskEngine
from .threat_intel import ThreatIntelEngine
from .soc_controller import SOCController
from .logger import NetScopeLogger
from .dashboard import NetworkDashboard
from .v20_live_bridge import LiveV20Bridge


# ============================================================
# ARGUMENTS
# ============================================================

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="NetScope V1.9.3 - Live SOC Network Analyzer"
    )

    parser.add_argument(
        "--protocol",
        choices=["tcp", "udp"],
        help="Filter by protocol",
    )

    parser.add_argument(
        "--ip",
        help="Filter by IP address",
    )

    parser.add_argument(
        "--port",
        type=int,
        help="Filter by source or destination port",
    )

    parser.add_argument(
        "--count",
        type=int,
        default=20,
        help="Number of packets to capture",
    )

    parser.add_argument(
        "--iface",
        help="Network interface to capture from",
    )

    parser.add_argument(
        "--ti-malicious",
        default="198.51.100.20",
        help="Comma-separated malicious IOC IPs",
    )

    parser.add_argument(
        "--ti-suspicious",
        default="203.0.113.50",
        help="Comma-separated suspicious IOC IPs",
    )

    return parser.parse_args()


# ============================================================
# FILTER
# ============================================================

def packet_matches(packet, args):
    if IP not in packet:
        return False

    ip = packet[IP]

    if args.protocol:
        if args.protocol == "tcp" and TCP not in packet:
            return False

        if args.protocol == "udp" and UDP not in packet:
            return False

    if args.ip:
        if ip.src != args.ip and ip.dst != args.ip:
            return False

    if args.port:
        if TCP in packet:
            if (
                packet[TCP].sport != args.port
                and packet[TCP].dport != args.port
            ):
                return False

        elif UDP in packet:
            if (
                packet[UDP].sport != args.port
                and packet[UDP].dport != args.port
            ):
                return False

        else:
            return False

    return True


# ============================================================
# PRIVATE IP
# ============================================================

def is_private_ip(ip):
    try:
        parts = ip.split(".")

        if len(parts) != 4:
            return False

        first = int(parts[0])
        second = int(parts[1])

        if first == 10:
            return True

        if first == 192 and second == 168:
            return True

        if first == 172 and 16 <= second <= 31:
            return True

        return False

    except (ValueError, IndexError):
        return False


# ============================================================
# DIRECTION
# ============================================================

def get_direction(source, destination):
    source_private = is_private_ip(source)
    destination_private = is_private_ip(destination)

    if source_private and not destination_private:
        return "OUTBOUND"

    if not source_private and destination_private:
        return "INBOUND"

    if source_private and destination_private:
        return "LOCAL"

    return "UNKNOWN"


# ============================================================
# IMPORT-SAFE ARGUMENTS
# ============================================================

def parse_arguments_for_import():
    """
    Pytest and other importers pass their own CLI arguments.
    Never let those arguments break `import src.analyzer`.
    """
    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument("--protocol", choices=["tcp", "udp"])
    parser.add_argument("--ip")
    parser.add_argument("--port", type=int)
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--iface")
    parser.add_argument("--ti-malicious", default="198.51.100.20")
    parser.add_argument("--ti-suspicious", default="203.0.113.50")

    parsed, _ = parser.parse_known_args()
    return parsed


# ============================================================
# GLOBAL COMPONENTS
# ============================================================

args = parse_arguments() if __name__ == "__main__" else parse_arguments_for_import()

stats = TrafficStatistics()
flow_tracker = FlowTracker()

# Legacy engine retained for regression compatibility.
security = SecurityDetector()

# Modern behavioral detections.
detection_engine = DetectionEngine()

# Threat Intelligence.
threat_intel = ThreatIntelEngine(
    malicious_ips={
        ip.strip()
        for ip in args.ti_malicious.split(",")
        if ip.strip()
    },
    suspicious_ips={
        ip.strip()
        for ip in args.ti_suspicious.split(",")
        if ip.strip()
    },
)

# Risk engine remains compatible with the V1.9.2 API.
risk_engine = RiskEngine(
    suspicious_ips={
        "203.0.113.50",
        "198.51.100.20",
    }
)

logger = NetScopeLogger()

dashboard = NetworkDashboard(
    max_packets=12,
    max_alerts=10,
)

# ============================================================
# V2.0 LIVE INVESTIGATION / RESPONSE / EVIDENCE
# ============================================================

v20_bridge = LiveV20Bridge(
    log_directory="logs",
    dashboard=dashboard,
)

# Keep recent live alerts for incident investigation evidence.
live_alerts = []

# Single SOC orchestration point.
soc = SOCController(
    logger=logger,
    dashboard=dashboard,
)


# ============================================================
# HELPERS
# ============================================================

def _profile_lists():
    attackers = sorted(
        soc.profile_engine.attackers.values(),
        key=lambda p: p.risk_score,
        reverse=True,
    )

    victims = sorted(
        soc.profile_engine.victims.values(),
        key=lambda p: p.risk_score,
        reverse=True,
    )

    return attackers[:5], victims[:5]


def _update_soc_dashboard():
    attackers, victims = _profile_lists()

    dashboard.update_profiles(
        attackers=attackers,
        victims=victims,
    )

    dashboard.update_timeline(
        soc.timeline.get_events()
    )

    summary = soc.incident_manager.get_summary()

    dashboard.update_incident_summary(
        summary
    )

    dashboard.update_flow_count(
        len(flow_tracker.flows)
    )

    dashboard.refresh()


# ============================================================
# PACKET CALLBACK
# ============================================================

def packet_callback(packet):
    """
    Process one live packet through the complete V1.9.3 SOC pipeline.

    A malformed packet is isolated so that one bad packet never
    terminates the capture loop.
    """

    try:
        if not packet_matches(packet, args):
            return

        if IP not in packet:
            return

        ip = packet[IP]

        source = ip.src
        destination = ip.dst
        size = len(packet)
        ttl = ip.ttl

        direction = get_direction(
            source,
            destination,
        )

        protocol = f"IP({ip.proto})"

        source_port = None
        destination_port = None

        flags = "-"
        raw_flags = "-"

        service = "Unknown"

        # --------------------------------------------------------
        # TCP
        # --------------------------------------------------------

        if TCP in packet:
            tcp = packet[TCP]

            protocol = "TCP"

            source_port = int(tcp.sport)
            destination_port = int(tcp.dport)

            raw_flags = tcp.sprintf(
                "%TCP.flags%"
            )

            flags = decode_tcp_flags(
                raw_flags
            )

            service = identify_service(
                protocol,
                source_port,
                destination_port,
                direction,
            )

        # --------------------------------------------------------
        # UDP
        # --------------------------------------------------------

        elif UDP in packet:
            udp = packet[UDP]

            protocol = "UDP"

            source_port = int(udp.sport)
            destination_port = int(udp.dport)

            service = identify_service(
                protocol,
                source_port,
                destination_port,
                direction,
            )

        # --------------------------------------------------------
        # LEGACY SECURITY
        # --------------------------------------------------------

        security_alerts = security.inspect_packet(
            source_ip=source,
            destination_ip=destination,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            direction=direction,
            tcp_flags=raw_flags,
        )

        # --------------------------------------------------------
        # MODERN DETECTION
        # --------------------------------------------------------

        detection_alerts = detection_engine.inspect_packet(
            source_ip=source,
            destination_ip=destination,
            destination_port=destination_port,
            protocol=protocol,
            size=size,
        )

        # --------------------------------------------------------
        # UNIFIED ALERT LIST
        # --------------------------------------------------------

        alerts = []

        if security_alerts:
            alerts.extend(security_alerts)

        if detection_alerts:
            alerts.extend(detection_alerts)

        # --------------------------------------------------------
        # SOC CONTROLLER
        #
        # SOCController now owns:
        #   TI matching
        #   risk scoring
        #   correlation
        #   incidents
        #   timeline
        #   profiles
        # --------------------------------------------------------

        # Threat Intelligence runs on both packet directions.
        ti_matches = threat_intel.inspect_packet(
            source_ip=source,
            destination_ip=destination,
        )

        # Add only actionable TI matches as SOC alerts.
        for match in ti_matches:
            if match.get("matched") and match.get("classification") in {
                "MALICIOUS",
                "SUSPICIOUS",
            }:
                alerts.append({
                    "rule_id": "NS-1008",
                    "alert_type": "THREAT_INTELLIGENCE",
                    "severity": (
                        "CRITICAL"
                        if match.get("classification") == "MALICIOUS"
                        else "MEDIUM"
                    ),
                    "confidence": match.get("confidence", "MEDIUM"),
                    "source_ip": source,
                    "destination_ip": destination,
                    "description": (
                        f"Threat intelligence match: "
                        f"{match.get('classification', 'UNKNOWN')} "
                        f"{match.get('ip', '')}"
                    ),
                    "evidence": match,
                })

        # Risk is calculated with the V1.9.2-compatible RiskEngine.
        try:
            risk = risk_engine.assess_packet(
                source_ip=source,
                destination_ip=destination,
                destination_port=destination_port,
                protocol=protocol,
                alerts=alerts,
                threat_intel=ti_matches,
            )
        except TypeError:
            # Backward-compatible fallback for an older RiskEngine.
            risk = risk_engine.assess_packet(
                source_ip=source,
                destination_ip=destination,
                destination_port=destination_port,
                protocol=protocol,
                alerts=alerts,
            )

        # The installed V1.8.7-compatible controller owns correlation,
        # incidents, timeline and profiles.
        soc.process_alerts(
            alerts,
            risk_score=risk.get("score", 0) if risk else 0,
        )

        # Keep alert evidence available for the V2.0 investigation layer.
        if alerts:
            live_alerts.extend(alerts)
            # Prevent unbounded memory growth during long captures.
            if len(live_alerts) > 500:
                del live_alerts[:-500]

        all_alerts = alerts

        # --------------------------------------------------------
        # V2.0 INCIDENT INVESTIGATION
        # --------------------------------------------------------
        #
        # Investigation starts only when the current packet produced
        # actionable security evidence. This keeps normal traffic cheap.
        #
        if alerts:
            incident = soc.incident_manager.find_incident(
                source,
                destination,
            )

            if incident is not None:
                related_alerts = [
                    alert
                    for alert in live_alerts
                    if (
                        alert.get("source_ip") == source
                        and alert.get("destination_ip") == destination
                    )
                ]

                # FlowTracker stores the active flows in a dictionary.
                related_flows = []
                for flow in getattr(flow_tracker, "flows", {}).values():
                    related_flows.append(flow)

                attacker_profile = soc.profile_engine.attackers.get(source)
                victim_profile = soc.profile_engine.victims.get(destination)

                report, plan = v20_bridge.investigate(
                    incident=incident,
                    alerts=related_alerts,
                    flows=related_flows,
                    timeline=soc.timeline,
                    attacker_profile=attacker_profile,
                    victim_profile=victim_profile,
                    threat_matches=ti_matches,
                )

                print(
                    f"[V2.0] Investigation {report.incident_id} | "
                    f"Risk={report.risk_score} | "
                    f"Severity={report.severity} | "
                    f"Response={plan.status}"
                )

        # --------------------------------------------------------
        # STATISTICS
        # --------------------------------------------------------

        stats.update(
            protocol=protocol,
            direction=direction,
            service=service,
            size=size,
        )

        # --------------------------------------------------------
        # FLOW
        # --------------------------------------------------------

        if TCP in packet or UDP in packet:
            flow_tracker.update(
                source,
                source_port,
                destination,
                destination_port,
                protocol,
                size,
            )

        # --------------------------------------------------------
        # SOC DASHBOARD
        # --------------------------------------------------------

        for alert in all_alerts:
            dashboard.update_alert(alert)

        if risk and risk.get("score", 0) > 0:
            dashboard.update_risk(risk)

        _update_soc_dashboard()

        # --------------------------------------------------------
        # PACKET LOG
        # --------------------------------------------------------

        logger.log_packet(
            source=source,
            destination=destination,
            protocol=protocol,
            source_port=source_port,
            destination_port=destination_port,
            service=service,
            direction=direction,
            size=size,
            ttl=ttl,
            tcp_flags=flags,
        )

        # --------------------------------------------------------
        # CONSOLE EVENT
        # --------------------------------------------------------

        if all_alerts:
            print(
                f"[ALERT] {source} -> {destination} | "
                f"{len(all_alerts)} alert(s)"
            )

            for alert in all_alerts:
                print(
                    f"        {alert.get('rule_id', 'UNKNOWN')} | "
                    f"{alert.get('severity', 'LOW')} | "
                    f"{alert.get('description', '')}"
                )

        if risk and risk.get("score", 0) > 0:
            print(
                f"[RISK]  {source} -> {destination} | "
                f"Score={risk.get('score', 0)} | "
                f"Severity={risk.get('severity', 'LOW')}"
            )

    except Exception as exc:
        # Never kill live capture because of one malformed packet.
        print(
            f"[WARN] Packet processing error: {exc}"
        )


# ============================================================
# FINAL SUMMARY
# ============================================================

def print_final_summary():

    detection_summary = (
        detection_engine.get_summary()
    )

    risk_summary = (
        risk_engine.get_summary()
    )

    soc_summary = (
        soc.get_summary()
    ) or {}

    print()
    print("=" * 72)
    print("                    NETSCOPE V1.9.3")
    print("=" * 72)

    print()
    print("LIVE CAPTURE")
    print("-" * 72)
    print(
        f"Packets Captured : {dashboard.packet_count}"
    )
    print(
        f"Total Bytes      : {dashboard.total_bytes}"
    )
    print(
        f"Flows            : {len(flow_tracker.flows)}"
    )

    print()
    print("DETECTION ENGINE")
    print("-" * 72)
    print(
        f"Detection Alerts : "
        f"{detection_summary.get('total_alerts', 0)}"
    )

    print()
    print("THREAT INTELLIGENCE")
    print("-" * 72)

    ti_summary = (
        threat_intel.get_summary()
    )

    for key, value in ti_summary.items():
        print(
            f"{str(key).replace('_', ' ').title():22}: {value}"
        )

    print()
    print("RISK ENGINE")
    print("-" * 72)
    print(
        f"Assessments      : "
        f"{risk_summary.get('total_assessments', 0)}"
    )
    print(
        f"Highest Risk     : "
        f"{risk_summary.get('highest_score', 0)}"
    )
    print(
        f"Highest Severity : "
        f"{risk_summary.get('highest_severity', 'LOW')}"
    )

    print()
    print("SOC")
    print("-" * 72)

    incident_summary = soc_summary.get(
        "incident_summary",
        {}
    )

    print(
        f"Incidents        : "
        f"{incident_summary.get('total_incidents', 0)}"
    )

    print(
        f"Active Incidents : "
        f"{incident_summary.get('active_incidents', 0)}"
    )

    print(
        f"Timeline Events  : "
        f"{soc_summary.get('timeline_summary', {}).get('event_count', 0)}"
    )

    print(
        f"Attackers        : "
        f"{soc_summary.get('profile_summary', {}).get('attacker_count', 0)}"
    )

    print(
        f"Victims          : "
        f"{soc_summary.get('profile_summary', {}).get('victim_count', 0)}"
    )

    print()
    print("=" * 72)
    print("                    NETSCOPE DONE")
    print("=" * 72)


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 72)
    print("                     NETSCOPE V1.9.3")
    print("=" * 72)

    print("Filters:")

    print(
        f"Protocol       : "
        f"{args.protocol.upper() if args.protocol else 'ALL'}"
    )

    print(
        f"IP             : "
        f"{args.ip if args.ip else 'ALL'}"
    )

    print(
        f"Port           : "
        f"{args.port if args.port else 'ALL'}"
    )

    print(
        f"Capture Limit  : {args.count}"
    )

    print(
        f"Interface      : "
        f"{args.iface if args.iface else 'DEFAULT'}"
    )

    print("-" * 72)
    print("Live SOC pipeline enabled")
    print("Legacy detection       : ENABLED")
    print("Modern detection       : ENABLED")
    print("Threat intelligence    : ENABLED")
    print("Risk scoring           : ENABLED")
    print("Incident correlation   : ENABLED")
    print("Attack timeline        : ENABLED")
    print("Attacker/Victim profile: ENABLED")
    print("Persistent SOC storage : ENABLED")
    print("V2.0 investigation    : ENABLED")
    print("Response planning      : ENABLED")
    print("Evidence preservation  : ENABLED")
    print("-" * 72)

    try:
        with dashboard.live(
            refresh_per_second=4
        ):
            sniff_kwargs = {
                "prn": packet_callback,
                "count": args.count,
            }

            if args.iface:
                sniff_kwargs["iface"] = args.iface

            sniff(**sniff_kwargs)

    except KeyboardInterrupt:
        print("\n[INFO] Capture interrupted by user.")

    finally:
        # Persist complete SOC state.
        soc.save()

        print_final_summary()


if __name__ == "__main__":
    main()
