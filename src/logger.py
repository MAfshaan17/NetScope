import json
from pathlib import Path
from datetime import datetime


class NetScopeLogger:

    def __init__(self, log_directory=None):

        if log_directory is None:

            self.log_directory = (
                Path(__file__).resolve().parent.parent
                / "logs"
            )

        else:

            self.log_directory = Path(
                log_directory
            )

        self.log_directory.mkdir(
            parents=True,
            exist_ok=True
        )

        self.packet_file = (
            self.log_directory
            / "packets.json"
        )

        self.flow_file = (
            self.log_directory
            / "flows.json"
        )

        self.alert_file = (
            self.log_directory
            / "security_alerts.json"
        )

    # ========================================
    # WRITE JSON
    # ========================================

    def _write_json(
        self,
        filename,
        data
    ):

        with open(
            filename,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                data,
                file,
                indent=4,
                ensure_ascii=False,
                default=str
            )

    # ========================================
    # READ JSON
    # ========================================

    def _read_json(self, filename):

        if not filename.exists():

            return []

        try:

            with open(
                filename,
                "r",
                encoding="utf-8"
            ) as file:

                data = json.load(file)

                if isinstance(data, list):

                    return data

                return []

        except (
            json.JSONDecodeError,
            OSError
        ):

            return []

    # ========================================
    # PACKETS
    # ========================================

    def log_packets(self, packets):

        output = []

        for packet in packets:

            if isinstance(
                packet,
                dict
            ):

                item = dict(packet)

            elif hasattr(
                packet,
                "to_dict"
            ):

                item = packet.to_dict()

            else:

                item = {
                    "packet":
                    str(packet)
                }

            if "timestamp" not in item:

                item["timestamp"] = (
                    datetime.now().isoformat(
                        timespec="seconds"
                    )
                )

            output.append(item)

        self._write_json(
            self.packet_file,
            output
        )

        return output

    # ========================================
    # SINGLE PACKET
    # ========================================

    def log_packet(
        self,
        source=None,
        destination=None,
        protocol=None,
        source_port=None,
        destination_port=None,
        service="Unknown",
        direction="UNKNOWN",
        size=0,
        ttl="-",
        flags="-",
        tcp_flags=None,
        **kwargs
    ):

        packet = {

            "timestamp":
                datetime.now().isoformat(
                    timespec="seconds"
                ),

            "source_ip":
                source,

            "destination_ip":
                destination,

            "protocol":
                protocol,

            "source_port":
                source_port,

            "destination_port":
                destination_port,

            "service":
                service,

            "direction":
                direction,

            "size":
                size,

            "ttl":
                ttl,

            "tcp_flags":
                (
                    tcp_flags
                    if tcp_flags is not None
                    else flags
                )
        }

        packet.update(kwargs)

        packets = self._read_json(
            self.packet_file
        )

        packets.append(packet)

        self._write_json(
            self.packet_file,
            packets
        )

        return packet

    # ========================================
    # FLOWS
    # ========================================

    def log_flows(self, flows):

        output = []

        if isinstance(
            flows,
            dict
        ):

            values = flows.values()

        elif isinstance(
            flows,
            list
        ):

            values = flows

        else:

            values = []

        for flow in values:

            if hasattr(
                flow,
                "to_dict"
            ):

                output.append(
                    flow.to_dict()
                )

            elif isinstance(
                flow,
                dict
            ):

                output.append(
                    dict(flow)
                )

            else:

                output.append({
                    "flow": str(flow)
                })

        self._write_json(
            self.flow_file,
            output
        )

        return output

    # ========================================
    # ALERTS
    # ========================================

    def log_alerts(self, alerts):

        output = []

        for alert in alerts:

            if hasattr(
                alert,
                "to_dict"
            ):

                item = alert.to_dict()

            elif isinstance(
                alert,
                dict
            ):

                item = dict(alert)

            else:

                item = {
                    "alert":
                    str(alert)
                }

            if "timestamp" not in item:

                item["timestamp"] = (
                    datetime.now().isoformat(
                        timespec="seconds"
                    )
                )

            output.append(item)

        self._write_json(
            self.alert_file,
            output
        )

        return output

    # ========================================
    # SINGLE ALERT
    # ========================================

    def log_alert(self, alert):

        return self.log_alerts(
            [alert]
        )

    # ========================================
    # CLEAR
    # ========================================

    def clear_logs(self):

        self._write_json(
            self.packet_file,
            []
        )

        self._write_json(
            self.flow_file,
            []
        )

        self._write_json(
            self.alert_file,
            []
        )