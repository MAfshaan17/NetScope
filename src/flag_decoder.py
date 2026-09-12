def decode_tcp_flags(flags):

    if flags is None:
        return "NONE"

    flags = str(flags).upper()

    decoded = []

    if "F" in flags:
        decoded.append("FIN")

    if "S" in flags:
        decoded.append("SYN")

    if "R" in flags:
        decoded.append("RST")

    if "P" in flags:
        decoded.append("PSH")

    if "A" in flags:
        decoded.append("ACK")

    if "U" in flags:
        decoded.append("URG")

    if "E" in flags:
        decoded.append("ECE")

    if "C" in flags:
        decoded.append("CWR")

    if not decoded:
        return "NONE"

    return ", ".join(decoded)