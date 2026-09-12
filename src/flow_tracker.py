from datetime import datetime


class FlowTracker:

    def __init__(self):

        self.flows = {}

    # ========================================
    # CREATE DIRECTION-INDEPENDENT KEY
    # ========================================

    def _flow_key(
        self,
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        protocol
    ):

        a = (
            source_ip,
            source_port
        )

        b = (
            destination_ip,
            destination_port
        )

        if a <= b:

            first = a
            second = b

        else:

            first = b
            second = a

        return (
            first,
            second,
            protocol
        )

    # ========================================
    # UPDATE FLOW
    # ========================================

    def update(
        self,
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        protocol,
        packet_size
    ):

        key = self._flow_key(
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            protocol
        )

        if key not in self.flows:

            self.flows[key] = {

                "source": key[0],

                "destination": key[1],

                "protocol": protocol,

                "packets": 0,

                "bytes": 0,

                "forward_packets": 0,

                "forward_bytes": 0,

                "reverse_packets": 0,

                "reverse_bytes": 0,

                "first_seen":
                    datetime.now().isoformat(
                        timespec="seconds"
                    ),

                "last_seen": None
            }

        flow = self.flows[key]

        flow["packets"] += 1

        flow["bytes"] += packet_size

        flow["last_seen"] = (
            datetime.now().isoformat(
                timespec="seconds"
            )
        )

        current = (
            source_ip,
            source_port
        )

        if current == flow["source"]:

            flow["forward_packets"] += 1

            flow["forward_bytes"] += packet_size

        else:

            flow["reverse_packets"] += 1

            flow["reverse_bytes"] += packet_size

    # ========================================
    # DISPLAY
    # ========================================

    def display_flows(self):

        if not self.flows:

            print("No flows detected.")

            return

        for flow in self.flows.values():

            print("----------------------------------------")

            print(
                f"Source      : "
                f"{flow['source'][0]}:"
                f"{flow['source'][1]}"
            )

            print(
                f"Destination : "
                f"{flow['destination'][0]}:"
                f"{flow['destination'][1]}"
            )

            print(
                f"Protocol    : "
                f"{flow['protocol']}"
            )

            print(
                f"Packets     : "
                f"{flow['packets']}"
            )

            print(
                f"Bytes       : "
                f"{flow['bytes']}"
            )

            print(
                f"Forward     : "
                f"{flow['forward_packets']} packets / "
                f"{flow['forward_bytes']} bytes"
            )

            print(
                f"Reverse     : "
                f"{flow['reverse_packets']} packets / "
                f"{flow['reverse_bytes']} bytes"
            )

            print(
                f"First Seen  : "
                f"{flow['first_seen']}"
            )

            print(
                f"Last Seen   : "
                f"{flow['last_seen']}"
            )

    def display(self):

        self.display_flows()

    # ========================================
    # OLD API COMPATIBILITY
    # ========================================

    def add_packet(
        self,
        source,
        source_port,
        destination,
        destination_port,
        protocol,
        size
    ):

        self.update(
            source,
            source_port,
            destination,
            destination_port,
            protocol,
            size
        )