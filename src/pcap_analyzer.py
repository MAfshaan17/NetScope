from scapy.all import rdpcap


class PCAPAnalyzer:

    def __init__(self, packet_processor):
        self.packet_processor = packet_processor

    def analyze(self, filename):

        packets = rdpcap(filename)

        print()
        print("=" * 40)
        print("          PCAP ANALYSIS")
        print("=" * 40)
        print(f"File    : {filename}")
        print(f"Packets : {len(packets)}")
        print("-" * 40)

        for packet in packets:
            self.packet_processor(packet)

        print("PCAP analysis complete.")

        return len(packets)