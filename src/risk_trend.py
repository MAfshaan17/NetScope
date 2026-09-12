"""NetScope V2.1 - persistent risk trend tracking."""
import json, os
from pathlib import Path
from datetime import datetime, timezone

class RiskTrend:
    def __init__(self, log_directory="logs"):
        self.path=Path(log_directory)/"risk_trend.json"; self.points=[]; self.load()
    def record(self, risk_score, severity="LOW", incident_id=None, timestamp=None):
        point={"timestamp":timestamp or datetime.now(timezone.utc).isoformat(),"risk_score":max(0,min(100,int(risk_score or 0))),"severity":str(severity).upper(),"incident_id":incident_id}
        self.points.append(point); self.points=self.points[-500:]; self.save(); return point
    def summary(self):
        scores=[p["risk_score"] for p in self.points]
        return {"points":len(scores),"current":scores[-1] if scores else 0,"max":max(scores) if scores else 0,"average":round(sum(scores)/len(scores),2) if scores else 0,"critical_count":sum(p["severity"]=="CRITICAL" for p in self.points),"high_count":sum(p["severity"]=="HIGH" for p in self.points)}
    def save(self):
        self.path.parent.mkdir(parents=True,exist_ok=True); tmp=self.path.with_suffix('.tmp')
        with tmp.open('w',encoding='utf-8') as f: json.dump(self.points,f,indent=2)
        os.replace(tmp,self.path)
    def load(self):
        try:
            self.points=json.loads(self.path.read_text(encoding='utf-8')) if self.path.exists() else []
        except (OSError,ValueError,TypeError): self.points=[]
