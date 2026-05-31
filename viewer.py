#!/usr/bin/env python3
'''Lightweight viewer for typoTwist JSON output (dnstwist_batch.py --json).

Usage:
    python3 viewer.py output.json
    python3 viewer.py output.json -p 9000
'''

import json
import argparse
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

DATA = {}   # domain -> list[dict]

HTML = '''<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>typoTwist Viewer</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:#f4f4f6;color:#1a1a2e;height:100vh;display:flex;flex-direction:column}
header{background:#1a1a2e;color:#fff;padding:12px 20px;display:flex;align-items:center;gap:16px}
header h1{font-size:1.05rem;font-weight:700;letter-spacing:.5px}
header .stats{font-size:.82rem;opacity:.6}
.layout{display:flex;flex:1;overflow:hidden}

/* sidebar */
.sidebar{width:270px;border-right:1px solid #e0e0e0;background:#fff;display:flex;flex-direction:column;flex-shrink:0}
.sidebar input{border:none;border-bottom:1px solid #eee;padding:10px 14px;font-size:.88rem;outline:none;background:#fafafa}
.sidebar input:focus{border-bottom-color:#4a7fd4;background:#fff}
.domain-list{overflow-y:auto;flex:1}
.d-item{padding:9px 14px;cursor:pointer;border-bottom:1px solid #f2f2f2;display:flex;justify-content:space-between;align-items:center;gap:8px}
.d-item:hover{background:#f0f4ff}
.d-item.active{background:#e8f0fe;border-left:3px solid #4a7fd4}
.d-item .name{font-size:.85rem;font-weight:500;word-break:break-all}
.d-item .cnt{font-size:.72rem;color:#888;background:#eee;padding:2px 7px;border-radius:10px;white-space:nowrap;flex-shrink:0}

/* main */
.main{flex:1;display:flex;flex-direction:column;overflow:hidden}
.toolbar{padding:10px 16px;background:#fff;border-bottom:1px solid #eee;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.toolbar h2{font-size:.9rem;font-weight:600;flex:1;min-width:120px;word-break:break-all}
.toolbar input,.toolbar select{border:1px solid #ddd;border-radius:4px;padding:5px 9px;font-size:.83rem;outline:none;background:#fafafa}
.toolbar input:focus,.toolbar select:focus{border-color:#4a7fd4;background:#fff}
.rcnt{font-size:.78rem;color:#999}
.wrap{overflow-y:auto;flex:1}
table{width:100%;border-collapse:collapse;font-size:.83rem}
thead th{position:sticky;top:0;background:#f8f8fa;padding:8px 12px;text-align:left;font-weight:600;border-bottom:2px solid #e8e8e8;color:#555}
tbody tr:hover{background:#f5f8ff}
td{padding:6px 12px;border-bottom:1px solid #f0f0f0;font-variant-numeric:tabular-nums}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:.73rem;background:#e8f0fe;color:#2b5daa;font-weight:500}
.ph{display:flex;align-items:center;justify-content:center;height:100%;color:#bbb;font-size:.92rem}
</style>
</head>
<body>
<header>
  <h1>typoTwist Viewer</h1>
  <span class="stats" id="stats"></span>
</header>
<div class="layout">
  <div class="sidebar">
    <input type="search" id="s-domain" placeholder="Filtrer les domaines…" oninput="filterDomains(this.value)">
    <div class="domain-list" id="dlist"></div>
  </div>
  <div class="main">
    <div class="toolbar" id="tb" style="display:none">
      <h2 id="cur-domain"></h2>
      <input type="search" id="s-perm" placeholder="Rechercher…" oninput="renderPerms()">
      <select id="fuz-sel" onchange="renderPerms()"><option value="">Tous les fuzzers</option></select>
      <span class="rcnt" id="rcnt"></span>
    </div>
    <div class="wrap" id="wrap"><div class="ph">← Sélectionner un domaine</div></div>
  </div>
</div>
<script>
let allDomains=[], currentPerms=[], current='';

async function init(){
  const r=await fetch('/api/domains');
  allDomains=await r.json();
  document.getElementById('stats').textContent=allDomains.length+' domaine'+(allDomains.length>1?'s':'');
  renderList(allDomains);
}

function renderList(list){
  document.getElementById('dlist').innerHTML=list.map(d=>
    `<div class="d-item${d.domain===current?' active':''}" onclick="select('${esc(d.domain)}')">
       <span class="name">${esc(d.domain)}</span><span class="cnt">${d.count}</span>
     </div>`).join('');
}

function filterDomains(q){
  q=q.toLowerCase();
  renderList(q?allDomains.filter(d=>d.domain.includes(q)):allDomains);
}

async function select(domain){
  current=domain;
  document.getElementById('tb').style.display='';
  document.getElementById('cur-domain').textContent=domain;
  document.getElementById('s-perm').value='';
  document.getElementById('fuz-sel').value='';
  const r=await fetch('/api/permutations/'+encodeURIComponent(domain));
  currentPerms=await r.json();
  const fuzzers=[...new Set(currentPerms.map(p=>p.fuzzer))].sort();
  const sel=document.getElementById('fuz-sel');
  sel.innerHTML='<option value="">Tous les fuzzers ('+fuzzers.length+')</option>'+
    fuzzers.map(f=>`<option value="${esc(f)}">${f}</option>`).join('');
  filterDomains(document.getElementById('s-domain').value);
  renderPerms();
}

function renderPerms(){
  const q=document.getElementById('s-perm').value.toLowerCase();
  const fz=document.getElementById('fuz-sel').value;
  let list=currentPerms;
  if(fz) list=list.filter(p=>p.fuzzer===fz);
  if(q) list=list.filter(p=>p.domain.includes(q));
  document.getElementById('rcnt').textContent=list.length+' / '+currentPerms.length;
  const wrap=document.getElementById('wrap');
  if(!list.length){wrap.innerHTML='<div class="ph">Aucun résultat</div>';return;}
  wrap.innerHTML='<table><thead><tr><th>Fuzzer</th><th>Domaine permuté</th></tr></thead><tbody>'+
    list.map(p=>`<tr><td><span class="badge">${esc(p.fuzzer)}</span></td><td>${esc(p.domain)}</td></tr>`).join('')+
    '</tbody></table>';
}

function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

init();
</script>
</body>
</html>'''


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        if path == '/':
            self._send(200, 'text/html; charset=utf-8', HTML.encode())
        elif path == '/api/domains':
            body = json.dumps(
                [{'domain': d, 'count': len(p)} for d, p in DATA.items()],
                ensure_ascii=False,
            ).encode()
            self._send(200, 'application/json', body)
        elif path.startswith('/api/permutations/'):
            domain = path[len('/api/permutations/'):]
            from urllib.parse import unquote
            domain = unquote(domain)
            perms = DATA.get(domain, [])
            self._send(200, 'application/json', json.dumps(perms, ensure_ascii=False).encode())
        else:
            self.send_error(404)

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def main():
    parser = argparse.ArgumentParser(description='Viewer for typoTwist JSON output')
    parser.add_argument('jsonfile', help='JSON file produced by dnstwist_batch.py --json')
    parser.add_argument('-p', '--port', type=int, default=8080, metavar='PORT')
    args = parser.parse_args()

    try:
        with open(args.jsonfile, encoding='utf-8') as f:
            records = json.load(f)
    except OSError as e:
        sys.exit('Cannot open {}: {}'.format(args.jsonfile, e.strerror))
    except json.JSONDecodeError as e:
        sys.exit('Invalid JSON in {}: {}'.format(args.jsonfile, e))

    for r in records:
        DATA[r['domain']] = r.get('permutations', [])

    total_perms = sum(len(v) for v in DATA.values())
    print('Loaded {} domain(s), {} permutation(s).'.format(len(DATA), total_perms))
    print('Open  http://localhost:{}/'.format(args.port))
    try:
        HTTPServer(('', args.port), Handler).serve_forever()
    except KeyboardInterrupt:
        print('\nStopped.')


if __name__ == '__main__':
    main()
