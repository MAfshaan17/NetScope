"""NetScope V2.1 - safe IOC extraction from SOC evidence."""
import ipaddress, re

DOMAIN_RE=re.compile(r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![A-Za-z0-9_-])")

class IOCExtractor:
    def extract(self, incident=None, alerts=None, flows=None, threat_matches=None):
        ips=set(); domains=set(); ports=set(); protocols=set(); sources=[]
        objects=[incident]+list(alerts or [])+list(flows or [])+list(threat_matches or [])
        for obj in objects:
            self._walk(obj, ips, domains, ports, protocols)
        return {"ips":sorted(ips),"domains":sorted(domains),"ports":sorted(ports),"protocols":sorted(protocols),"count":len(ips)+len(domains)+len(ports)+len(protocols)}

    def _walk(self,obj,ips,domains,ports,protocols,key=""):
        if obj is None: return
        if hasattr(obj,"to_dict"): obj=obj.to_dict()
        if isinstance(obj,dict):
            for k,v in obj.items(): self._walk(v,ips,domains,ports,protocols,str(k).lower())
            return
        if isinstance(obj,(list,tuple,set)):
            for v in obj: self._walk(v,ips,domains,ports,protocols,key)
            return
        if isinstance(obj,bool): return
        s=str(obj)
        try:
            ip=ipaddress.ip_address(s)
            if not ip.is_multicast and not ip.is_unspecified: ips.add(str(ip)); return
        except ValueError: pass
        if key in {"source_port","destination_port","sport","dport","port","ports"}:
            try:
                p=int(s)
                if 0<=p<=65535: ports.add(p)
            except ValueError: pass
        if key in {"protocol","proto"} and len(s)<=20: protocols.add(s.upper())
        for d in DOMAIN_RE.findall(s): domains.add(d.lower())
