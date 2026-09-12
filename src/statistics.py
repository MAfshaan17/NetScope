from collections import defaultdict


class TrafficStatistics:

    def __init__(self):

        self.total_packets = 0

        self.total_bytes = 0

        self.protocol_counts = defaultdict(int)

        self.direction_counts = defaultdict(int)

        self.service_counts = defaultdict(int)

    # ========================================
    # UPDATE
    # ========================================

    def update(
        self,
        protocol,
        direction,
        service,
        size
    ):

        self.total_packets += 1

        self.total_bytes += size

        self.protocol_counts[
            protocol
        ] += 1

        self.direction_counts[
            direction
        ] += 1

        if service != "Unknown":

            self.service_counts[
                service
            ] += 1

    # ========================================
    # DISPLAY
    # ========================================

    def display(self):

        print("\n========================================")
        print("          TRAFFIC STATISTICS")
        print("========================================")

        print(
            f"Total Packets     : "
            f"{self.total_packets}"
        )

        print(
            f"Total Bytes       : "
            f"{self.total_bytes} bytes"
        )

        print("\nProtocols:")

        if not self.protocol_counts:

            print("  No protocol data")

        else:

            for protocol, count in sorted(
                self.protocol_counts.items()
            ):

                print(
                    f"  {protocol:<12}: "
                    f"{count}"
                )

        print("\nDirections:")

        if not self.direction_counts:

            print("  No direction data")

        else:

            for direction, count in sorted(
                self.direction_counts.items()
            ):

                print(
                    f"  {direction:<12}: "
                    f"{count}"
                )

        print("\nServices:")

        if not self.service_counts:

            print("  No services detected")

        else:

            for service, count in sorted(
                self.service_counts.items()
            ):

                print(
                    f"  {service:<15}: "
                    f"{count}"
                )

        print("========================================")