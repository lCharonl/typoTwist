#!/usr/bin/env python3
'''Viewer for typoTwist JSONL output (dnstwist_batch.py).

Supports files of any size via a companion .idx index:
  - If <file>.idx exists, domains and offsets are loaded from it (fast).
  - Otherwise the JSONL is scanned once to build the index in memory.

Usage:
    python3 viewer.py output.jsonl
    python3 viewer.py output.jsonl -p 9000
'''

import json
import re
import argparse
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, unquote, parse_qs

# ---------------------------------------------------------------------------
# Index
# ---------------------------------------------------------------------------

DOMAINS   = []          # ordered list of domain strings
OFFSETS   = {}          # domain -> byte offset in JSONL
COUNTS    = {}          # domain -> permutation count (from .idx)
DATA_PATH = ''          # path to the JSONL file
IS_JSONL  = True        # False = small JSON array loaded entirely in RAM
MEM_DATA  = {}          # only used when IS_JSONL is False


def _load_index_file(idx_path):
    domains, offsets, counts = [], {}, {}
    with open(idx_path, encoding='utf-8') as f:
        for line in f:
            parts = line.rstrip('\n').split('\t')
            if len(parts) >= 2 and parts[0] and parts[1].isdigit():
                domain = parts[0]
                domains.append(domain)
                offsets[domain] = int(parts[1])
                counts[domain] = int(parts[2]) if len(parts) >= 3 and parts[2].isdigit() else -1
    return domains, offsets, counts


def _scan_jsonl(path):
    '''Walk the JSONL file once to extract domain names and byte offsets.'''
    domains, offsets = [], {}
    pat = re.compile(rb'"domain"\s*:\s*"([^"\\]+)"')
    with open(path, 'rb') as f:
        while True:
            pos = f.tell()
            line = f.readline()
            if not line:
                break
            m = pat.search(line, 0, 300)
            if m:
                domain = m.group(1).decode('utf-8', errors='replace')
                domains.append(domain)
                offsets[domain] = pos
    return domains, offsets


def load_data(path):
    global DOMAINS, OFFSETS, COUNTS, DATA_PATH, IS_JSONL, MEM_DATA

    DATA_PATH = path

    # Detect format: JSON array starts with '[', JSONL starts with '{'
    with open(path, 'rb') as f:
        first = f.read(1)

    if first == b'[':
        # Small JSON array — load entirely in RAM
        IS_JSONL = False
        with open(path, encoding='utf-8') as f:
            records = json.load(f)
        for r in records:
            d = r['domain']
            DOMAINS.append(d)
            MEM_DATA[d] = r.get('permutations', [])
            COUNTS[d] = len(MEM_DATA[d])
        OFFSETS = {}
        return

    # JSONL — try companion .idx first
    IS_JSONL = True
    idx_path = path + '.idx'
    try:
        DOMAINS, OFFSETS, COUNTS = _load_index_file(idx_path)
        print('Index loaded from {} ({} domains).'.format(idx_path, len(DOMAINS)))
    except OSError:
        print('No .idx found — scanning {} to build index...'.format(path), flush=True)
        DOMAINS, OFFSETS = _scan_jsonl(path)
        COUNTS = {d: -1 for d in DOMAINS}
        print('Index built ({} domains).'.format(len(DOMAINS)))


def get_permutations(domain):
    if not IS_JSONL:
        return MEM_DATA.get(domain, [])
    offset = OFFSETS.get(domain)
    if offset is None:
        return []
    with open(DATA_PATH, encoding='utf-8') as f:
        f.seek(offset)
        line = f.readline()
    try:
        return json.loads(line).get('permutations', [])
    except json.JSONDecodeError:
        return []


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

HTML = '''<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>typoTwist Viewer</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:#f4f4f6;color:#1a1a2e;height:100vh;display:flex;flex-direction:column}
header{background:#1a1a2e;color:#fff;padding:11px 20px;display:flex;align-items:center;gap:16px}
header h1{font-size:1.05rem;font-weight:700;letter-spacing:.4px}
header .stats{font-size:.8rem;opacity:.55}
.layout{display:flex;flex:1;overflow:hidden}

/* sidebar */
.sidebar{width:270px;border-right:1px solid #e0e0e0;background:#fff;display:flex;flex-direction:column;flex-shrink:0}
.sidebar input{border:none;border-bottom:1px solid #eee;padding:10px 14px;font-size:.88rem;outline:none;background:#fafafa}
.sidebar input:focus{border-bottom-color:#4a7fd4;background:#fff}
.domain-list{overflow-y:auto;flex:1}
.d-item{padding:8px 14px;cursor:pointer;border-bottom:1px solid #f2f2f2;display:flex;justify-content:space-between;align-items:center;gap:8px}
.d-item:hover{background:#f0f4ff}
.d-item.active{background:#e8f0fe;border-left:3px solid #4a7fd4}
.d-item .name{font-size:.84rem;font-weight:500;word-break:break-all}
.d-item .cnt{font-size:.72rem;color:#888;background:#eee;padding:2px 7px;border-radius:10px;white-space:nowrap;flex-shrink:0}
.pagination{display:flex;gap:6px;padding:8px 10px;border-top:1px solid #eee;justify-content:center;flex-wrap:wrap}
.pagination button{border:1px solid #ddd;background:#fff;border-radius:4px;padding:3px 10px;font-size:.8rem;cursor:pointer}
.pagination button:hover{background:#f0f4ff;border-color:#4a7fd4}
.pagination button.active{background:#4a7fd4;color:#fff;border-color:#4a7fd4}
.pagination .info{font-size:.78rem;color:#999;align-self:center}

/* main */
.main{flex:1;display:flex;flex-direction:column;overflow:hidden}
.toolbar{padding:9px 16px;background:#fff;border-bottom:1px solid #eee;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.toolbar h2{font-size:.9rem;font-weight:600;flex:1;min-width:120px;word-break:break-all}
.toolbar input,.toolbar select{border:1px solid #ddd;border-radius:4px;padding:5px 9px;font-size:.83rem;outline:none;background:#fafafa}
.toolbar input:focus,.toolbar select:focus{border-color:#4a7fd4;background:#fff}
.rcnt{font-size:.78rem;color:#999;white-space:nowrap}
.wrap{overflow-y:auto;flex:1}
table{width:100%;border-collapse:collapse;font-size:.83rem}
thead th{position:sticky;top:0;background:#f8f8fa;padding:8px 12px;text-align:left;font-weight:600;border-bottom:2px solid #e8e8e8;color:#555}
tbody tr:hover{background:#f5f8ff}
td{padding:5px 12px;border-bottom:1px solid #f0f0f0}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:.73rem;background:#e8f0fe;color:#2b5daa;font-weight:500}
.ph{display:flex;align-items:center;justify-content:center;height:100%;color:#bbb;font-size:.92rem}
.loading{color:#aaa;font-style:italic;padding:20px 16px}
</style>
</head>
<body>
<header>
  <h1>typoTwist Viewer</h1>
  <span class="stats" id="stats"></span>
</header>
<div class="layout">
  <div class="sidebar">
    <input type="search" id="s-domain" placeholder="Rechercher un domaine…" oninput="onSearch(this.value)">
    <div class="domain-list" id="dlist"></div>
    <div class="pagination" id="pages"></div>
  </div>
  <div class="main">
    <div class="toolbar" id="tb" style="display:none">
      <h2 id="cur-domain"></h2>
      <input type="search" id="s-perm" placeholder="Filtrer permutations…" oninput="renderPerms()">
      <select id="fuz-sel" onchange="renderPerms()"><option value="">Tous les fuzzers</option></select>
      <span class="rcnt" id="rcnt"></span>
    </div>
    <div class="wrap" id="wrap"><div class="ph">← Sélectionner un domaine</div></div>
  </div>
</div>
<script>
const PAGE_SIZE = 100;
let totalDomains = 0, currentQuery = '', currentPage = 0;
let currentPerms = [], currentDomain = '';
let searchTimer = null;

async function fetchDomains(q, offset) {
  const url = '/api/domains?q=' + encodeURIComponent(q) + '&offset=' + offset + '&limit=' + PAGE_SIZE;
  const r = await fetch(url);
  return r.json();  // {total, items: [{domain, count}]}
}

async function renderSidebar() {
  const {total, items} = await fetchDomains(currentQuery, currentPage * PAGE_SIZE);
  totalDomains = total;

  document.getElementById('stats').textContent =
    total.toLocaleString() + ' domaine' + (total !== 1 ? 's' : '');

  document.getElementById('dlist').innerHTML = items.map(d =>
    `<div class="d-item${d.domain === currentDomain ? ' active' : ''}" onclick="selectDomain('${esc(d.domain)}')">
       <span class="name">${esc(d.domain)}</span><span class="cnt">${d.count.toLocaleString()}</span>
     </div>`).join('') || '<div class="loading">Aucun résultat</div>';

  const totalPages = Math.ceil(total / PAGE_SIZE);
  const pages = document.getElementById('pages');
  if (totalPages <= 1) { pages.innerHTML = ''; return; }

  const MAX_BTN = 7;
  let btns = '', p = currentPage;
  const start = Math.max(0, Math.min(p - 3, totalPages - MAX_BTN));
  const end   = Math.min(totalPages, start + MAX_BTN);
  if (start > 0) btns += `<button onclick="goPage(0)">1</button><span class="info">…</span>`;
  for (let i = start; i < end; i++)
    btns += `<button class="${i===p?'active':''}" onclick="goPage(${i})">${i+1}</button>`;
  if (end < totalPages) btns += `<span class="info">…</span><button onclick="goPage(${totalPages-1})">${totalPages}</button>`;
  btns += `<span class="info">${(p*PAGE_SIZE+1).toLocaleString()}–${Math.min((p+1)*PAGE_SIZE,total).toLocaleString()} / ${total.toLocaleString()}</span>`;
  pages.innerHTML = btns;
}

function goPage(n) { currentPage = n; renderSidebar(); }

function onSearch(q) {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => { currentQuery = q; currentPage = 0; renderSidebar(); }, 250);
}

async function selectDomain(domain) {
  currentDomain = domain;
  document.getElementById('tb').style.display = '';
  document.getElementById('cur-domain').textContent = domain;
  document.getElementById('s-perm').value = '';
  document.getElementById('fuz-sel').value = '';
  document.getElementById('wrap').innerHTML = '<div class="loading">Chargement…</div>';

  const r = await fetch('/api/permutations/' + encodeURIComponent(domain));
  currentPerms = await r.json();

  const fuzzers = [...new Set(currentPerms.map(p => p.fuzzer))].sort();
  const sel = document.getElementById('fuz-sel');
  sel.innerHTML = '<option value="">Tous (' + fuzzers.length + ' fuzzers)</option>' +
    fuzzers.map(f => `<option value="${esc(f)}">${f}</option>`).join('');

  renderSidebar();
  renderPerms();
}

function renderPerms() {
  const q   = document.getElementById('s-perm').value.toLowerCase();
  const fz  = document.getElementById('fuz-sel').value;
  let list  = currentPerms;
  if (fz) list = list.filter(p => p.fuzzer === fz);
  if (q)  list = list.filter(p => p.domain.includes(q));

  document.getElementById('rcnt').textContent =
    list.length.toLocaleString() + ' / ' + currentPerms.length.toLocaleString();

  const wrap = document.getElementById('wrap');
  if (!list.length) { wrap.innerHTML = '<div class="ph">Aucun résultat</div>'; return; }

  wrap.innerHTML =
    '<table><thead><tr><th>Fuzzer</th><th>Domaine permuté</th></tr></thead><tbody>' +
    list.map(p =>
      `<tr><td><span class="badge">${esc(p.fuzzer)}</span></td><td>${esc(p.domain)}</td></tr>`
    ).join('') +
    '</tbody></table>';
}

function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

renderSidebar();
</script>
</body>
</html>'''


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path
        qs     = parse_qs(parsed.query)

        if path == '/':
            self._send(200, 'text/html; charset=utf-8', HTML.encode())

        elif path == '/api/domains':
            q      = qs.get('q', [''])[0].lower()
            offset = int(qs.get('offset', ['0'])[0])
            limit  = int(qs.get('limit', ['100'])[0])
            # server-side filter on in-memory domain list
            filtered = [d for d in DOMAINS if q in d] if q else DOMAINS
            total    = len(filtered)
            items    = filtered[offset: offset + limit]
            # build counts: from OFFSETS we can't know count without reading,
            # but for JSONL we store count in a second index or skip it.
            # Use MEM_DATA when available (small JSON), else show -1.
            def _count(d):
                return COUNTS.get(d, -1)
            body = json.dumps(
                {'total': total,
                 'items': [{'domain': d, 'count': _count(d)} for d in items]},
                ensure_ascii=False,
            ).encode()
            self._send(200, 'application/json', body)

        elif path.startswith('/api/permutations/'):
            domain = unquote(path[len('/api/permutations/'):])
            perms  = get_permutations(domain)
            self._send(200, 'application/json',
                       json.dumps(perms, ensure_ascii=False).encode())

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


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description='Viewer for typoTwist JSONL output')
    parser.add_argument('jsonfile', help='JSONL (or JSON) file from dnstwist_batch.py')
    parser.add_argument('-p', '--port', type=int, default=8080, metavar='PORT')
    args = parser.parse_args()

    try:
        load_data(args.jsonfile)
    except OSError as e:
        sys.exit('Cannot open {}: {}'.format(args.jsonfile, e.strerror))
    except (json.JSONDecodeError, ValueError) as e:
        sys.exit('Invalid file {}: {}'.format(args.jsonfile, e))

    total_perms = sum(len(v) for v in MEM_DATA.values()) if not IS_JSONL else '(on demand)'
    print('Domains : {:,}'.format(len(DOMAINS)))
    print('Perms   : {}'.format(
        '{:,}'.format(total_perms) if isinstance(total_perms, int) else total_perms))
    print('Open    : http://localhost:{}/'.format(args.port))
    try:
        HTTPServer(('', args.port), Handler).serve_forever()
    except KeyboardInterrupt:
        print('\nStopped.')


if __name__ == '__main__':
    main()
