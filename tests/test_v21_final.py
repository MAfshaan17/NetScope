from src.v21_final import NetScopeFinalSOC

def test_v21_full_stack(tmp_path):
    soc=NetScopeFinalSOC(tmp_path)
    incident={"incident_id":"NS-INC-1","source_ip":"10.0.0.10","destination_ip":"10.0.0.20","risk_score":85,"severity":"CRITICAL"}
    alerts=[{"alert_id":"A1","alert_type":"PORT_SCAN","rule_id":"NS-1001","description":"Port scan","evidence":{"ports":[22,80],"protocol":"TCP"}}, {"alert_id":"A2","alert_type":"THREAT_INTELLIGENCE","rule_id":"NS-1008","description":"TI match","evidence":{}}]
    report,plan=soc.investigate_incident(incident,alerts=alerts,threat_matches=[{"matched_ip":"10.0.0.10","classification":"MALICIOUS"}])
    assert report.incident_id=="NS-INC-1"
    assert plan.approval_required is True
    case=soc.get_case("NS-INC-1")
    assert case["case_id"]=="NS-CASE-0001"
    assert "RECONNAISSANCE" in case["classification"]["stages"]
    assert 22 in case["iocs"]["ports"]
    assert soc.dashboard_snapshot()["cases"]["active"]==1

def test_case_workflow(tmp_path):
    soc=NetScopeFinalSOC(tmp_path)
    incident={"incident_id":"I2","source_ip":"1.1.1.1","destination_ip":"10.0.0.2","risk_score":60,"severity":"HIGH"}
    soc.investigate_incident(incident,alerts=[])
    soc.add_note("I2","Review source host")
    assert len(soc.get_case("I2")["notes"])==1
    soc.transition_case("I2","CONTAINMENT_PENDING")
    assert soc.get_case("I2")["status"]=="CONTAINMENT_PENDING"
