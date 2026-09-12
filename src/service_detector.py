TCP_SERVICES = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS/TLS",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    8080: "HTTP-ALT",
}


UDP_SERVICES = {
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    123: "NTP",
    161: "SNMP",
    500: "IKE",
    1900: "SSDP",
    5353: "mDNS",
}


def identify_service(
    protocol,
    source_port,
    destination_port,
    direction=None
):

    protocol = str(protocol).upper()

    try:
        source_port = int(source_port)
    except (ValueError, TypeError):
        source_port = None

    try:
        destination_port = int(destination_port)
    except (ValueError, TypeError):
        destination_port = None

    # ========================================
    # TCP
    # ========================================

    if protocol == "TCP":

        if destination_port in TCP_SERVICES:

            return TCP_SERVICES[
                destination_port
            ]

        if source_port in TCP_SERVICES:

            return TCP_SERVICES[
                source_port
            ]

    # ========================================
    # UDP
    # ========================================

    if protocol == "UDP":

        if destination_port in UDP_SERVICES:

            return UDP_SERVICES[
                destination_port
            ]

        if source_port in UDP_SERVICES:

            return UDP_SERVICES[
                source_port
            ]

    return "Unknown"