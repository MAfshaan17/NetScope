from src.threat_intel import ThreatIntelEngine

def test_malicious_match():
    e = ThreatIntelEngine(malicious_ips={"203.0.113.50"})
    r = e.inspect_ip("203.0.113.50")
    assert r["matched"] and r["classification"] == "MALICIOUS"
    assert r["confidence"] == "HIGH"

def test_suspicious_match():
    e = ThreatIntelEngine(suspicious_ips={"198.51.100.20"})
    r = e.inspect_ip("198.51.100.20")
    assert r["matched"] and r["classification"] == "SUSPICIOUS"

def test_unknown():
    r = ThreatIntelEngine().inspect_ip("10.0.0.25")
    assert not r["matched"] and r["classification"] == "UNKNOWN"

def test_packet_both_directions():
    e = ThreatIntelEngine(malicious_ips={"203.0.113.50"}, suspicious_ips={"198.51.100.20"})
    r = e.inspect_packet("10.0.0.1", "203.0.113.50")
    assert len(r) == 1 and r[0]["direction"] == "DESTINATION"

def test_metadata():
    e = ThreatIntelEngine(ioc_ips={"203.0.113.77": {
        "classification": "MALICIOUS", "confidence": "HIGH",
        "source": "TEST_FEED", "description": "Known scanner",
        "tags": ["scanner", "recon"]}})
    r = e.inspect_ip("203.0.113.77")
    assert r["source"] == "TEST_FEED"
    assert r["tags"] == ["scanner", "recon"]

def test_add_remove():
    e = ThreatIntelEngine()
    e.add_ip("203.0.113.88")
    assert e.contains("203.0.113.88")
    assert e.remove_ip("203.0.113.88")
    assert not e.contains("203.0.113.88")

def test_summary():
    e = ThreatIntelEngine(malicious_ips={"203.0.113.50"}, suspicious_ips={"198.51.100.20"})
    e.inspect_ip("203.0.113.50"); e.inspect_ip("198.51.100.20")
    s = e.get_summary()
    assert s["ioc_count"] == 2 and s["match_count"] == 2
    assert s["malicious_matches"] == 1 and s["suspicious_matches"] == 1

def test_reset():
    e = ThreatIntelEngine(malicious_ips={"203.0.113.50"})
    e.inspect_ip("203.0.113.50"); e.reset_matches()
    assert e.get_summary()["match_count"] == 0
