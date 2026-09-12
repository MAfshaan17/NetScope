"""NetScope V2.1 - deterministic attack classification."""
from collections import OrderedDict

STAGES = OrderedDict([
    ("PORT_SCAN", "RECONNAISSANCE"),
    ("NS-1001", "RECONNAISSANCE"),
    ("SYN_SCAN", "SCANNING"),
    ("NS-1002", "SCANNING"),
    ("DNS_BURST", "DISCOVERY"),
    ("NS-1004", "DISCOVERY"),
    ("HIGH_CONNECTION_RATE", "CONNECTION_FLOOD"),
    ("NS-1005", "CONNECTION_FLOOD"),
    ("TRAFFIC_BURST", "TRAFFIC_FLOOD"),
    ("NS-1007", "TRAFFIC_FLOOD"),
    ("HIGH_ACTIVITY", "HIGH_ACTIVITY"),
    ("NS-1003", "HIGH_ACTIVITY"),
    ("THREAT_INTELLIGENCE", "THREAT_INTELLIGENCE"),
    ("NS-1008", "THREAT_INTELLIGENCE"),
])

class AttackClassifier:
    def classify_alert(self, alert):
        value = str(self._get(alert, "alert_type", "")).upper()
        rule = str(self._get(alert, "rule_id", "")).upper()
        stage = STAGES.get(value) or STAGES.get(rule) or "OTHER"
        category = {
            "RECONNAISSANCE":"RECONNAISSANCE", "SCANNING":"SCANNING",
            "DISCOVERY":"DISCOVERY", "CONNECTION_FLOOD":"DENIAL_OF_SERVICE",
            "TRAFFIC_FLOOD":"DENIAL_OF_SERVICE", "HIGH_ACTIVITY":"ANOMALOUS_ACTIVITY",
            "THREAT_INTELLIGENCE":"THREAT_INTELLIGENCE", "OTHER":"UNCLASSIFIED",
        }[stage]
        return {"stage": stage, "category": category, "alert_type": value or "UNKNOWN", "rule_id": rule or "UNKNOWN"}

    def classify(self, alerts=None, incident=None):
        alerts = alerts or []
        stages=[]; categories=[]; details=[]
        for alert in alerts:
            item=self.classify_alert(alert); details.append(item)
            if item["stage"] not in stages: stages.append(item["stage"])
            if item["category"] not in categories: categories.append(item["category"])
        # Preserve chronological/semantic order from the alert stream.
        return {"primary_category": self._primary(categories), "stages": stages, "categories": categories, "details": details}

    @staticmethod
    def _primary(categories):
        order=["THREAT_INTELLIGENCE","DENIAL_OF_SERVICE","SCANNING","RECONNAISSANCE","DISCOVERY","ANOMALOUS_ACTIVITY","UNCLASSIFIED"]
        for x in order:
            if x in categories: return x
        return "UNCLASSIFIED"

    @staticmethod
    def _get(obj,key,default=None):
        return obj.get(key,default) if isinstance(obj,dict) else getattr(obj,key,default)
