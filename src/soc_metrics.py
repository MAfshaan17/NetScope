"""NetScope V2.1 - SOC metrics."""
from collections import Counter

class SOCMetrics:
    def __init__(self): self.reset()
    def reset(self): self.incidents=0; self.alerts=0; self.risk_scores=[]; self.severities=Counter(); self.categories=Counter(); self.iocs=0
    def record(self, incident=None, alerts=None, classification=None, ioc_count=0):
        self.incidents+=1; self.alerts+=len(alerts or []); score=self._get(incident,'risk_score',0) or 0; self.risk_scores.append(int(score)); sev=str(self._get(incident,'severity','LOW')).upper(); self.severities[sev]+=1
        if classification: self.categories.update(classification.get('categories',[]))
        self.iocs+=int(ioc_count or 0)
    def summary(self):
        return {'incidents':self.incidents,'alerts':self.alerts,'average_risk':round(sum(self.risk_scores)/len(self.risk_scores),2) if self.risk_scores else 0,'max_risk':max(self.risk_scores) if self.risk_scores else 0,'severities':dict(self.severities),'attack_categories':dict(self.categories),'iocs':self.iocs}
    @staticmethod
    def _get(o,k,d=None): return o.get(k,d) if isinstance(o,dict) else getattr(o,k,d)
