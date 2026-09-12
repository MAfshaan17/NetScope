"""NetScope V2.1 - lightweight SOC case management."""
import json, os
from pathlib import Path
from datetime import datetime, timezone

TRANSITIONS={"NEW":{"INVESTIGATING","CLOSED"},"INVESTIGATING":{"CONTAINMENT_PENDING","CLOSED"},"CONTAINMENT_PENDING":{"CONTAINED","INVESTIGATING","CLOSED"},"CONTAINED":{"RESOLVED","INVESTIGATING","CLOSED"},"RESOLVED":{"CLOSED","INVESTIGATING"},"CLOSED":set()}

class CaseManager:
    def __init__(self, log_directory="logs"):
        self.path=Path(log_directory)/"soc_cases.json"; self.cases={}; self.load()
    def upsert(self, incident, report=None, plan=None, classification=None, iocs=None):
        iid=self._get(incident,"incident_id","UNKNOWN"); now=datetime.now(timezone.utc).isoformat(); old=self.cases.get(iid,{})
        case={**old,"case_id":old.get("case_id",f"NS-CASE-{len(self.cases)+1:04d}"),"incident_id":iid,"status":old.get("status","INVESTIGATING"),"severity":str(self._get(incident,"severity","LOW")).upper(),"risk_score":int(self._get(incident,"risk_score",0) or 0),"source_ip":self._get(incident,"source_ip",""),"destination_ip":self._get(incident,"destination_ip",""),"classification":classification or old.get("classification",{}),"iocs":iocs or old.get("iocs",{}),"report":self._dict(report) if report else old.get("report"),"response_plan":self._dict(plan) if plan else old.get("response_plan"),"notes":old.get("notes",[]),"created_at":old.get("created_at",now),"updated_at":now}
        self.cases[iid]=case; self.save(); return case
    def add_note(self, incident_id, note, author="analyst"):
        case=self.cases[incident_id]; case.setdefault("notes",[]).append({"text":str(note),"author":author,"timestamp":datetime.now(timezone.utc).isoformat()}); case["updated_at"]=datetime.now(timezone.utc).isoformat(); self.save(); return case
    def transition(self, incident_id, status):
        case=self.cases[incident_id]; status=str(status).upper()
        if status not in TRANSITIONS.get(case.get("status","NEW"),set()): raise ValueError(f"Invalid case transition: {case.get('status')} -> {status}")
        case["status"]=status; case["updated_at"]=datetime.now(timezone.utc).isoformat(); self.save(); return case
    def get(self, incident_id): return self.cases.get(incident_id)
    def list_active(self): return [c for c in self.cases.values() if c.get("status")!="CLOSED"]
    def summary(self):
        return {"total":len(self.cases),"active":len(self.list_active()),"critical":sum(c.get("severity")=="CRITICAL" for c in self.cases.values()),"pending_approval":sum((c.get("response_plan") or {}).get("status")=="PENDING_APPROVAL" for c in self.cases.values())}
    def save(self):
        self.path.parent.mkdir(parents=True,exist_ok=True); tmp=self.path.with_suffix('.tmp'); tmp.write_text(json.dumps(self.cases,indent=2,default=str),encoding='utf-8'); os.replace(tmp,self.path)
    def load(self):
        try: self.cases=json.loads(self.path.read_text(encoding='utf-8')) if self.path.exists() else {}
        except (OSError,ValueError,TypeError): self.cases={}
    @staticmethod
    def _get(o,k,d=None): return o.get(k,d) if isinstance(o,dict) else getattr(o,k,d)
    @staticmethod
    def _dict(o): return o.to_dict() if hasattr(o,'to_dict') else o
