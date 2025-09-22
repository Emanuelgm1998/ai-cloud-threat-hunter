#!/usr/bin/env python3
# ai-cloud-threat-hunter
# Single-file, senior-quality script for real-time log threat hunting (Cloud/SysOps).
# Author: Emanuel (ai-cloud-threat-hunter)
# License: MIT
"""
AI-Cloud Threat Hunter (single script)

- Sigue logs en tiempo real (Nginx access.log o syslog).
- Reglas: brute force (SSH), tormentas 404/403, rutas sospechosas.
- Anomalías de tasa: EWMA + z-score sin dependencias pesadas.
- Dashboard en vivo con 'rich' si está instalado; si no, modo texto.
- Exportación periódica y al salir: JSON/Markdown.

Ejemplos:
  python ai_cloud_threat_hunter.py --log sample_access.log --replay --speed 30 --threshold 2 --export-md report.md
  python ai_cloud_threat_hunter.py --log /var/log/syslog --format syslog --window 300 --threshold 5 --export-json report.json
"""

from __future__ import annotations
import argparse, collections, datetime as dt, io, json, math, os, re, signal, sys, threading, time
from dataclasses import dataclass, field
from typing import Deque, Dict, Iterable, List, Optional

# UI opcional (rich)
try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.align import Align
    HAS_RICH = True
except Exception:
    HAS_RICH = False
    Console = Live = Table = Panel = Align = None

console = Console() if HAS_RICH else None

# -------------------------
# Parsers
# -------------------------
NGINX_COMMON_LOG = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>.+?)\] "(?P<method>[A-Z]+) (?P<path>\S+)(?: HTTP/\d\.\d)?" (?P<status>\d{3}) (?P<size>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)
SYSLOG_LINE = re.compile(
    r'^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>[\w\-/]+)(?:\[\d+\])?:\s+(?P<msg>.+)$'
)
FAILED_LOGIN = re.compile(r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})')
ACCEPTED_LOGIN = re.compile(r'Accepted password for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})')
SUSPICIOUS_PATHS = [
    '/wp-login.php','/wp-admin','/admin','/phpmyadmin','/.env','/config.php','/.git','/.DS_Store','/server-status','/actuator','/jenkins','/boaform/admin/formLogin'
]

def parse_nginx(line:str)->Optional[Dict[str,str]]:
    m = NGINX_COMMON_LOG.search(line)
    if not m: return None
    d = m.groupdict()
    # Nginx time: 21/Sep/2025:10:12:00 +0000
    try: t = dt.datetime.strptime(d['time'].split()[0], "%d/%b/%Y:%H:%M:%S")
    except: t = dt.datetime.utcnow()
    return {'type':'nginx','ip':d.get('ip','-'),'time':t.isoformat(),'method':d.get('method','-'),
            'path':d.get('path','-'),'status':d.get('status','-'),'ua':d.get('ua','-')}

def parse_syslog(line:str)->Optional[Dict[str,str]]:
    m = SYSLOG_LINE.search(line)
    if not m: return None
    d = m.groupdict()
    now_year = dt.datetime.utcnow().year
    ts = f"{d['mon']} {d['day']} {now_year} {d['time']}"
    try: t = dt.datetime.strptime(ts, "%b %d %Y %H:%M:%S")
    except: t = dt.datetime.utcnow()
    info = {'type':'syslog','time':t.isoformat(),'host':d.get('host','-'),
            'proc':d.get('proc','-'),'msg':d.get('msg','-'),'ip':None,'user':None,'event':None}
    fm = FAILED_LOGIN.search(d['msg'])
    if fm: info['ip']=fm.group('ip'); info['user']=fm.group('user'); info['event']='failed_login'; return info
    am = ACCEPTED_LOGIN.search(d['msg'])
    if am: info['ip']=am.group('ip'); info['user']=am.group('user'); info['event']='accepted_login'; return info
    return info

# -------------------------
# Detección & scoring
# -------------------------
@dataclass
class EWMA:
    alpha: float = 0.3; mean: float = 0.0; var: float = 1.0; initialized: bool = False
    def update(self,x:float):
        if not self.initialized: self.mean=x; self.var=1.0; self.initialized=True; return
        prev=self.mean; self.mean=self.alpha*x+(1-self.alpha)*self.mean
        self.var=self.alpha*((x-prev)**2)+(1-self.alpha)*self.var
    def zscore(self,x:float)->float:
        import math; std=math.sqrt(max(self.var,1e-6)); return (x-self.mean)/std if std>0 else 0.0

@dataclass
class Alert: ts:str; severity:str; kind:str; ip:Optional[str]; detail:str; score:float
@dataclass
class Stats:
    total_lines:int=0; total_events:int=0; total_alerts:int=0
    per_ip_count:Dict[str,int]=field(default_factory=lambda: collections.defaultdict(int))
    last_alerts:Deque[Alert]=field(default_factory=lambda: collections.deque(maxlen=100))

class ThreatHunter:
    def __init__(self, window:int=300, threshold:int=5, ewma_alpha:float=0.3):
        self.window=window; self.threshold=threshold; self.ewma_alpha=ewma_alpha
        self.stats=Stats()
        self.events_by_ip:Dict[str,Deque[float]]=collections.defaultdict(lambda: collections.deque())
        self.failed_logins_by_ip:Dict[str,Deque[float]]=collections.defaultdict(lambda: collections.deque())
        self.status_by_ip:Dict[str,Dict[str,Deque[float]]]=collections.defaultdict(lambda: collections.defaultdict(lambda: collections.deque()))
        self.rate_model:Dict[str,EWMA]=collections.defaultdict(lambda: EWMA(alpha=self.ewma_alpha))
        self._stop=threading.Event()

    def stop(self): self._stop.set()

    def ingest_event(self, ev:Dict[str,str]):
        self.stats.total_events+=1; now=time.time(); ip=ev.get('ip')
        if ev['type']=='nginx':
            path=ev.get('path',''); status=ev.get('status',''); self._record_request(ip,status,now)
            if any(susp in path for susp in SUSPICIOUS_PATHS): self._alert('medium','suspicious_path',ip,f"path={path}",6.0)
            if status in ('403','404'): self._check_status_storm(ip,status,now)
            self._check_rate_anomaly(ip,now)
        elif ev['type']=='syslog':
            event=ev.get('event')
            if event=='failed_login' and ip: self._record_failed_login(ip,now); self._check_bruteforce(ip,now)
            elif event=='accepted_login' and ip: self._record_request(ip,'200',now)

    def _prune_window(self,dq:Deque[float],now:float):
        w=self.window
        while dq and now-dq[0]>w: dq.popleft()

    def _record_request(self,ip:Optional[str],status:str,now:float):
        if not ip: return
        dq=self.events_by_ip[ip]; dq.append(now); self._prune_window(dq,now); self.stats.per_ip_count[ip]+=1
        dqs=self.status_by_ip[ip][status]; dqs.append(now); self._prune_window(dqs,now)

    def _check_status_storm(self,ip:Optional[str],status:str,now:float):
        if not ip: return
        dq=self.status_by_ip[ip][status]; self._prune_window(dq,now)
        if len(dq)>=self.threshold:
            sev='medium' if status=='404' else 'high'
            self._alert(sev,f'{status}_storm',ip,f'{len(dq)} {status}s in {self.window}s',7.0+(len(dq)-self.threshold))

    def _record_failed_login(self,ip:str,now:float):
        dq=self.failed_logins_by_ip[ip]; dq.append(now); self._prune_window(dq,now)

    def _check_bruteforce(self,ip:str,now:float):
        dq=self.failed_logins_by_ip[ip]; self._prune_window(dq,now)
        if len(dq)>=self.threshold:
            self._alert('critical','bruteforce',ip,f'{len(dq)} failed logins in {self.window}s',9.0+0.5*(len(dq)-self.threshold))

    def _check_rate_anomaly(self,ip:Optional[str],now:float):
        if not ip: return
        dq=self.events_by_ip[ip]; self._prune_window(dq,now)
        rate=len(dq)/max(self.window,1); model=self.rate_model[ip]; model.update(rate); z=model.zscore(rate)
        if z>3.0 and len(dq)>self.threshold: self._alert('high','rate_anomaly',ip,f'z={z:.2f}, rate={rate:.3f} req/s',min(10.0,7.5+z))

    def _alert(self,severity:str,kind:str,ip:Optional[str],detail:str,score:float):
        a=Alert(ts=dt.datetime.utcnow().isoformat(),severity=severity,kind=kind,ip=ip,detail=detail,score=round(float(score),2))
        self.stats.total_alerts+=1; self.stats.last_alerts.append(a)
        if not HAS_RICH: print(f"[ALERT] {a.ts} {severity.upper()} {kind} ip={ip} {detail} score={a.score}")

    def to_report(self)->Dict:
        top_ips=sorted(self.stats.per_ip_count.items(), key=lambda kv: kv[1], reverse=True)[:10]
        return {'generated_at':dt.datetime.utcnow().isoformat(),'window_seconds':self.window,'threshold':self.threshold,
                'totals':{'lines_processed':self.stats.total_lines,'events_parsed':self.stats.total_events,'alerts':self.stats.total_alerts},
                'top_ips':[{'ip':ip,'events':cnt} for ip,cnt in top_ips],
                'recent_alerts':[a.__dict__ for a in list(self.stats.last_alerts)]}

# -------------------------
# Lectura de logs
# -------------------------
def iter_lines_follow(fp:io.TextIOBase, stop_event:threading.Event, replay:bool=False, speed:int=10)->Iterable[str]:
    if replay:
        fp.seek(0)
        for line in fp:
            yield line.rstrip('\n'); time.sleep(1.0/max(speed,1))
    else:
        fp.seek(0, os.SEEK_END)
    while not stop_event.is_set():
        pos=fp.tell(); line=fp.readline()
        if not line: time.sleep(0.2); fp.seek(pos)
        else: yield line.rstrip('\n')

def autodetect_format(sample:str)->str:
    if NGINX_COMMON_LOG.search(sample): return 'nginx'
    if SYSLOG_LINE.search(sample): return 'syslog'
    return 'auto'

def parse_line(line:str, default_fmt:str)->Optional[Dict[str,str]]:
    if default_fmt=='nginx':
        ev=parse_nginx(line)
    elif default_fmt=='syslog':
        ev=parse_syslog(line)
    else:
        ev=parse_nginx(line) or parse_syslog(line)
    return ev

# -------------------------
# UI
# -------------------------
def build_table(hunter:'ThreatHunter'):
    table=Table(title="AI Cloud Threat Hunter — Live Dashboard", expand=True)
    table.add_column("Metric"); table.add_column("Value", justify="right")
    r=hunter.to_report()
    table.add_row("Lines processed", str(r['totals']['lines_processed']))
    table.add_row("Events parsed", str(r['totals']['events_parsed']))
    table.add_row("Alerts", str(r['totals']['alerts']))
    table.add_row("Window (s)", str(r['window_seconds'])); table.add_row("Threshold", str(r['threshold']))
    top_str=", ".join([f"{x['ip']}({x['events']})" for x in r['top_ips']]) if r['top_ips'] else "-"
    table.add_row("Top IPs", top_str)

    table2=Table(title="Recent Alerts (last 100)", expand=True)
    for c in ["Time","Severity","Type","IP","Detail","Score"]: table2.add_column(c, no_wrap=(c in ["Time","Severity","Type","IP","Score"]))
    for a in list(hunter.stats.last_alerts)[-15:]:
        table2.add_row(a.ts, a.severity.upper(), a.kind, a.ip or "-", a.detail, f"{a.score:.2f}")

    outer=Table.grid(expand=True); outer.add_row(table); outer.add_row(table2); return outer

def print_plain(hunter:'ThreatHunter'):
    r=hunter.to_report()
    print("="*80); print("AI Cloud Threat Hunter — Live")
    print(f"Lines: {r['totals']['lines_processed']}  Events: {r['totals']['events_parsed']}  Alerts: {r['totals']['alerts']}")
    print(f"Window: {r['window_seconds']}s  Threshold: {r['threshold']}")
    if r['top_ips']: print("Top IPs:", ", ".join([f"{x['ip']}({x['events']})" for x in r['top_ips']]))
    else: print("Top IPs: -")
    print("- Recent alerts:")
    for a in list(hunter.stats.last_alerts)[-10:]:
        print(f"  [{a.severity.upper()}] {a.kind} ip={a.ip or '-'} :: {a.detail} :: score={a.score:.2f} @ {a.ts}")

# -------------------------
# Export
# -------------------------
def export_json(path:str,data:Dict):
    with open(path,'w',encoding='utf-8') as f: json.dump(data,f,indent=2)

def export_md(path:str,data:Dict):
    lines=[f"# AI Cloud Threat Hunter Report\n", f"- Generated at: `{data.get('generated_at','')}`",
           f"- Window (s): `{data.get('window_seconds','')}`  |  Threshold: `{data.get('threshold','')}`\n",
           "## Totals", f"- Lines processed: **"+str(data.get('totals',{}).get('lines_processed',0))+"**",
           f"- Events parsed: **"+str(data.get('totals',{}).get('events_parsed',0))+"**",
           f"- Alerts: **"+str(data.get('totals',{}).get('alerts',0))+"**\n", "## Top IPs"]
    if data.get('top_ips'): lines += [f"- `{x['ip']}` → {x['events']} events" for x in data['top_ips']]
    else: lines.append("- None")
    lines += ["","## Recent Alerts"]
    if data.get('recent_alerts'):
        for a in data['recent_alerts'][-50:]:
            lines.append(f"- **{a['severity'].upper()}** | `{a['kind']}` | ip=`{a.get('ip','-')}` | score={a.get('score',0)}")
            lines.append(f"  - {a.get('detail','')} @ {a.get('ts','')}")
    else: lines.append("- None")
    with open(path,'w',encoding='utf-8') as f: f.write("\n".join(lines))

# -------------------------
# Main
# -------------------------
def run(args):
    hunter=ThreatHunter(window=args.window, threshold=args.threshold, ewma_alpha=args.ewma_alpha)
    stop_event=threading.Event()
    def _sig(_s,_f): stop_event.set(); hunter.stop()
    signal.signal(signal.SIGINT,_sig); signal.signal(signal.SIGTERM,_sig)

    # Abrir log
    if not os.path.isfile(args.log):
        print(f"[!] Log file not found: {args.log}", file=sys.stderr); sys.exit(1)

    with open(args.log,'r',encoding='utf-8',errors='ignore') as fp:
        pos=fp.tell(); first=fp.readline(); fp.seek(pos)
        fmt=args.format
        if fmt=='auto': fmt=autodetect_format(first or '')
        if fmt=='auto': fmt='nginx'
        if HAS_RICH: console.log(f"[bold]Format[/bold]: {fmt}")
        else: print(f"Format: {fmt}")

        it=iter_lines_follow(fp, stop_event, replay=args.replay, speed=args.speed)
        last_export=time.time(); refresh_ts=time.time(); refresh_interval=max(0.5, args.refresh)

        if HAS_RICH:
            with Live(Panel(Align.center("Starting..."), title="AI Cloud Threat Hunter"), refresh_per_second=8, console=console) as live:
                for line in it:
                    if stop_event.is_set(): break
                    hunter.stats.total_lines+=1
                    ev=parse_line(line, fmt)
                    if ev: hunter.ingest_event(ev)
                    now=time.time()
                    if now-refresh_ts>=refresh_interval:
                        live.update(build_table(hunter)); refresh_ts=now
                    if args.export_json or args.export_md:
                        if now-last_export>=args.export_every:
                            data=hunter.to_report()
                            if args.export_json: export_json(args.export_json,data)
                            if args.export_md: export_md(args.export_md,data)
                            last_export=now
        else:
            last_print=0
            for line in it:
                if stop_event.is_set(): break
                hunter.stats.total_lines+=1
                ev=parse_line(line, fmt)
                if ev: hunter.ingest_event(ev)
                now=time.time()
                if now-last_print>=refresh_interval:
                    print_plain(hunter); last_print=now
                if args.export_json or args.export_md:
                    if now-last_export>=args.export_every:
                        data=hunter.to_report()
                        if args.export_json: export_json(args.export_json,data)
                        if args.export_md: export_md(args.export_md,data)
                        last_export=now

    # Export final
    if args.export_json or args.export_md:
        data=hunter.to_report()
        if args.export_json: export_json(args.export_json,data)
        if args.export_md: export_md(args.export_md,data)
    if HAS_RICH: console.print(Panel("Exiting. Reports exported.", title="AI Cloud Threat Hunter"))
    else: print("Exiting. Reports exported.")

def build_argparser():
    p=argparse.ArgumentParser(description="AI Cloud Threat Hunter (single-file)")
    p.add_argument('--log', required=True, help='Path to log file (nginx access.log, syslog, etc.)')
    p.add_argument('--format', choices=['auto','nginx','syslog'], default='auto', help='Log format')
    p.add_argument('--window', type=int, default=300, help='Sliding window seconds')
    p.add_argument('--threshold', type=int, default=5, help='Umbral para detecciones (storms/bruteforce)')
    p.add_argument('--ewma-alpha', type=float, default=0.3, help='EWMA alpha para modelo de tasa')
    p.add_argument('--refresh', type=float, default=1.0, help='UI refresh (s)')
    p.add_argument('--export-json', type=str, default=None, help='Exporta JSON periódico')
    p.add_argument('--export-md', type=str, default=None, help='Exporta Markdown periódico')
    p.add_argument('--export-every', type=int, default=30, help='Intervalo export (s)')
    p.add_argument('--replay', action='store_true', help='Reproducir archivo desde el inicio')
    p.add_argument('--speed', type=int, default=25, help='Velocidad replay (líneas/seg)')
    return p

if __name__=='__main__':
    args=build_argparser().parse_args()
    try: run(args)
    except KeyboardInterrupt: pass
