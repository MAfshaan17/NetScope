"""NetScope V2.1 FINAL - unified SOC intelligence layer.

Adds classification, IOC extraction, risk trends, case management and metrics
without replacing the stable V1.x/V2.0 detection pipeline.
"""
from .v20_soc import V20SOC
from .attack_classifier import AttackClassifier
from .ioc_extractor import IOCExtractor
from .risk_trend import RiskTrend
from .case_manager import CaseManager
from .soc_metrics import SOCMetrics

class NetScopeFinalSOC:
    def __init__(self, log_directory="logs"):
        self.v20=V20SOC(log_directory=log_directory)
        self.classifier=AttackClassifier(); self.ioc_extractor=IOCExtractor(); self.risk_trend=RiskTrend(log_directory); self.cases=CaseManager(log_directory); self.metrics=SOCMetrics()
    def investigate_incident(self, incident, alerts=None, flows=None, timeline=None, attacker_profile=None, victim_profile=None, threat_matches=None):
        report,plan=self.v20.investigate_incident(incident,alerts,flows,timeline,attacker_profile,victim_profile,threat_matches)
        classification=self.classifier.classify(alerts,incident); iocs=self.ioc_extractor.extract(incident,alerts,flows,threat_matches)
        # Keep the V2.0 report immutable; attach the V2.1 intelligence as a non-breaking extension.
        if hasattr(report,'to_dict'):
            report_dict=report.to_dict(); report_dict['classification']=classification; report_dict['iocs']=iocs; report_dict['approval_required']=getattr(plan,'approval_required',True)
        self.risk_trend.record(report.risk_score,report.severity,report.incident_id,report.timestamp)
        case=self.cases.upsert(incident,report,plan,classification,iocs)
        self.metrics.record(incident,alerts,classification,iocs['count'])
        return report,plan
    def add_note(self,incident_id,note,author='analyst'): return self.cases.add_note(incident_id,note,author)
    def transition_case(self,incident_id,status): return self.cases.transition(incident_id,status)
    def get_case(self,incident_id): return self.cases.get(incident_id)
    def dashboard_snapshot(self): return {'cases':self.cases.summary(),'risk_trend':self.risk_trend.summary(),'metrics':self.metrics.summary(),'investigations':self.v20.get_summary()}
    def get_report(self,incident_id): return self.v20.get_report(incident_id)
    def get_plan(self,incident_id): return self.v20.get_plan(incident_id)
