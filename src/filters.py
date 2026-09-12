def matches_protocol(packet, protocol):

    if protocol is None:
        return True

    protocol = protocol.upper()

    if protocol == "TCP":
        from scapy.all import TCP
        return TCP in packet

    if protocol == "UDP":
        from scapy.all import UDP
        return UDP in packet

    return False


def matches_ip(packet, ip_address):

    from scapy.all import IP

    if IP not in packet:
        return False

    return (
        packet[IP].src == ip_address
        or packet[IP].dst == ip_address
    )


def matches_port(packet, port):

    from scapy.all import TCP, UDP

    if TCP in packet:
        return (
            packet[TCP].sport == port
            or packet[TCP].dport == port
        )

    if UDP in packet:
        return (
            packet[UDP].sport == port
            or packet[UDP].dport == port
        )

    return False