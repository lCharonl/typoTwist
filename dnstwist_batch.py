#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Batch wrapper around dnstwist: reads domains from a CSV file, runs permutation
generation for each, and writes results in JSON Lines format.

Output files (pair):
  output.jsonl        — one JSON object per line: {"domain": "...", "permutations": [...]}
  output.jsonl.idx    — lightweight index: domain<TAB>byte_offset (one per line)

The .idx file enables fast resume (no need to scan the full JSONL) and lets
viewer.py load permutations on demand without reading the whole file.

Resume: re-running the same command skips already-done domains automatically.
Delete output.jsonl (and .idx) to start from scratch.
'''

import csv
import json
import argparse
import sys
import os
import signal
import time
import threading
from multiprocessing import Pool

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dnstwist


# ---------------------------------------------------------------------------
# Pretty logging (colors + per-domain threat-intel stats)
# ---------------------------------------------------------------------------

# Nameserver/MX fingerprints of well-known domain parking / resale services.
PARKING_NS = (
    'parkingcrew', 'sedo', 'above.com', 'park-mx', 'bodis', 'dan.com',
    'afternic', 'hugedomains', 'parklogic', 'cashparking', 'voodoo',
    'fabulous', 'undeveloped', 'sav.com', 'namedrive', 'parkingpage',
    'parking', 'parkingcrew.net',
)


class Palette:
    '''ANSI colors, neutralized to empty strings when color is disabled.'''
    def __init__(self, enabled):
        codes = dict(
            RESET='\033[0m', BOLD='\033[1m', DIM='\033[2m',
            RED='\033[31m', GREEN='\033[32m', YELLOW='\033[33m',
            BLUE='\033[34m', MAGENTA='\033[35m', CYAN='\033[36m', GREY='\033[90m',
        )
        for name, code in codes.items():
            setattr(self, name, code if enabled else '')


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def perm_stats(perms):
    '''Return (lookalikes, mx, parked, idn) for one domain's permutation list.

    The original domain (fuzzer '*original') is excluded from the lookalike
    count. "mx" = has a mail server configured (can receive e-mail). "parked" =
    nameserver/MX matches a known parking/resale provider. "idn" = punycode.
    '''
    lookalikes = mx = parked = idn = 0
    for p in perms:
        if p.get('fuzzer') == '*original':
            continue
        lookalikes += 1
        if p.get('dns_mx'):
            mx += 1
        fingerprint = ' '.join(_as_list(p.get('dns_ns')) + _as_list(p.get('dns_mx'))).lower()
        if any(tag in fingerprint for tag in PARKING_NS):
            parked += 1
        dom = p.get('domain')
        if isinstance(dom, str) and dom.startswith('xn--'):
            idn += 1
    return lookalikes, mx, parked, idn


# ---------------------------------------------------------------------------
# Multiprocessing worker
# ---------------------------------------------------------------------------

def _worker_init():
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def _scan_worker(item):
    domain, kwargs = item
    try:
        result = dnstwist.run(**kwargs)
        return domain, result if result is not None else [], None
    except Exception as e:
        return domain, [], str(e)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def read_domains(filepath):
    '''Read domains from CSV. Handles "domain" and "rank,domain" (Tranco) layouts.'''
    domains = []
    with open(filepath, encoding='utf-8') as f:
        for row in csv.reader(f):
            if not row:
                continue
            if row[0].lstrip().startswith('#'):
                continue
            domain = row[-1].strip()
            if domain and not domain.startswith('#') and not domain.isdigit():
                domains.append(domain)
    return domains


def load_done_domains(output_path):
    '''Return the set of already-processed domains.

    Reads from the fast .idx file when it exists; falls back to scanning JSONL.
    '''
    idx_path = output_path + '.idx'
    done = set()

    if os.path.exists(idx_path):
        with open(idx_path, encoding='utf-8') as f:
            for line in f:
                parts = line.rstrip('\n').split('\t')
                if parts and parts[0]:
                    done.add(parts[0])
        return done

    if not os.path.exists(output_path):
        return done
    with open(output_path, encoding='utf-8') as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if 'domain' in obj:
                    done.add(obj['domain'])
            except json.JSONDecodeError:
                print('WARNING: skipping malformed line {} in {}'.format(lineno, output_path),
                      file=sys.stderr)
    return done


def build_scan_kwargs(domain, args):
    kwargs = {
        'domain': domain,
        'output': dnstwist.devnull,
    }
    if args.no_dns:
        kwargs['format'] = 'list'
    if args.all:
        kwargs['all'] = True
    if args.banners:
        kwargs['banners'] = True
    if args.dictionary:
        kwargs['dictionary'] = args.dictionary
    if args.fuzzers:
        kwargs['fuzzers'] = args.fuzzers
    if args.geoip:
        kwargs['geoip'] = True
    if args.lsh:
        kwargs['lsh'] = args.lsh
    if args.lsh_url:
        kwargs['lsh_url'] = args.lsh_url
    if args.mxcheck:
        kwargs['mxcheck'] = True
    if args.registered:
        kwargs['registered'] = True
    if args.unregistered:
        kwargs['unregistered'] = True
    if not args.no_dns and args.threads:
        kwargs['threads'] = args.threads
    if args.whois:
        kwargs['whois'] = True
    if args.tld:
        kwargs['tld'] = args.tld
    if args.nameservers:
        kwargs['nameservers'] = args.nameservers
    if args.useragent:
        kwargs['useragent'] = args.useragent
    return kwargs


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog=os.path.basename(sys.argv[0]),
        description='Batch dnstwist — reads domains from CSV, writes JSONL + .idx index',
        epilog='Re-running resumes from where it left off (uses .idx for fast skip).',
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=32),
    )
    parser.add_argument('input', metavar='CSV',
        help='Input CSV file (one domain per line, or rank,domain)')
    parser.add_argument('-o', '--output', metavar='FILE', required=True,
        help='Output JSONL file (companion .idx index created automatically)')
    parser.add_argument('--no-dns', action='store_true',
        help='Skip DNS — generate permutations only (recommended for large runs)')
    parser.add_argument('-W', '--workers', type=int, default=1, metavar='N',
        help='Parallel worker processes (default: 1; use os.cpu_count() for max)')
    parser.add_argument('--no-color', action='store_true',
        help='Disable ANSI colors in progress output')

    # dnstwist pass-through options
    parser.add_argument('-a', '--all', action='store_true',
        help='Include all DNS records instead of the first ones')
    parser.add_argument('-b', '--banners', action='store_true',
        help='Fetch HTTP and SMTP service banners')
    parser.add_argument('-d', '--dictionary', metavar='FILE',
        help='Extra permutations from dictionary FILE')
    parser.add_argument('--fuzzers', metavar='LIST',
        help='Comma-separated list of fuzzers to use')
    parser.add_argument('-g', '--geoip', action='store_true',
        help='GeoIP country lookup')
    parser.add_argument('--lsh', metavar='ALGO', nargs='?', const='ssdeep',
        choices=['ssdeep', 'tlsh'],
        help='HTML similarity: ssdeep or tlsh (default: ssdeep)')
    parser.add_argument('--lsh-url', metavar='URL',
        help='Override URL for LSH reference page')
    parser.add_argument('-m', '--mxcheck', action='store_true',
        help='Check MX for email interception')
    parser.add_argument('-r', '--registered', action='store_true',
        help='Only registered domains in output')
    parser.add_argument('-u', '--unregistered', action='store_true',
        help='Only unregistered domains in output')
    parser.add_argument('-t', '--threads', type=int, metavar='NUM',
        default=dnstwist.THREAD_COUNT_DEFAULT,
        help='DNS scanner threads per domain (default: %d)' % dnstwist.THREAD_COUNT_DEFAULT)
    parser.add_argument('-w', '--whois', action='store_true',
        help='WHOIS lookup (registrar + creation date)')
    parser.add_argument('--tld', metavar='FILE',
        help='TLD swap dictionary file')
    parser.add_argument('--nameservers', metavar='LIST',
        help='DNS/DoH servers to query (comma-separated)')
    parser.add_argument('--useragent', metavar='STRING',
        default=dnstwist.USER_AGENT_STRING,
        help='User-Agent string for HTTP requests')

    args = parser.parse_args()

    if args.registered and args.unregistered:
        parser.error('--registered and --unregistered are mutually exclusive')
    if args.lsh_url and not args.lsh:
        parser.error('--lsh-url requires --lsh')
    if args.no_dns and (args.registered or args.unregistered or args.banners
                        or args.geoip or args.lsh or args.mxcheck or args.whois):
        parser.error('--no-dns is incompatible with DNS-dependent options')
    if args.workers < 1:
        parser.error('--workers must be >= 1')
    if not args.no_dns and not dnstwist.MODULE_DNSPYTHON:
        parser.error(
            'DNSPython is not available — DNS lookups would be unreliable (no MX/NS).\n'
            '  Activate the project virtualenv:  source .venv/bin/activate\n'
            '  or install it:                    pip install dnspython\n'
            '  (use --no-dns to generate permutations only, without any DNS).')

    try:
        all_domains = read_domains(args.input)
    except OSError as e:
        parser.error('cannot open {}: {}'.format(args.input, e.strerror.lower()))

    if not all_domains:
        parser.error('no domains found in {}'.format(args.input))

    done_domains = load_done_domains(args.output)
    remaining = [d for d in all_domains if d not in done_domains]

    total_all = len(all_domains)
    n_done = len(done_domains)
    n_remaining = len(remaining)

    tty = sys.stderr.isatty()
    use_color = tty and not args.no_color and os.environ.get('NO_COLOR') is None
    c = Palette(use_color)

    mode = ('permutations only (no DNS)' if args.no_dns else
            'registered domains only'    if args.registered else
            'unregistered domains only'  if args.unregistered else
            'full DNS scan')

    def _row(label, value, value_color=''):
        print('  {d}{lab:<9}{r}: {vc}{val}{r}'.format(
            d=c.GREY, r=c.RESET, lab=label, vc=value_color, val=value), file=sys.stderr)

    bar = '  {g}{line}{r}'.format(g=c.GREY, line='─' * 46, r=c.RESET)
    print(file=sys.stderr)
    print('  {b}{cy}typoTwist{r} {d}· batch DNS fuzzing{r}'.format(
        b=c.BOLD, cy=c.CYAN, d=c.DIM, r=c.RESET), file=sys.stderr)
    print(bar, file=sys.stderr)
    _row('source', args.input)
    _row('targets', '{} domain(s)'.format(total_all), c.BOLD)
    _row('mode', mode, c.MAGENTA)
    _row('workers', '{}{}'.format(args.workers, ' (parallel)' if args.workers > 1 else ''))
    _row('output', args.output)
    if n_done:
        _row('resume', '{}/{} already done · {} remaining'.format(
            n_done, total_all, n_remaining), c.YELLOW)
    print(bar, file=sys.stderr)
    print(file=sys.stderr)

    if not remaining:
        print('  {g}All domains already processed. Nothing to do.{r}'.format(
            g=c.GREEN, r=c.RESET), file=sys.stderr)
        return

    n_scanned = 0
    n_errors = 0
    tot_look = tot_mx = tot_park = tot_idn = 0
    idx_path = args.output + '.idx'
    DW = 22                      # domain column width
    CLR = '\r\033[K' if tty else ''

    _SPIN = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    _spin_stop  = threading.Event()
    _first_done = threading.Event()

    def _fmt_dur(secs):
        secs = int(secs)
        return '{}m{:02d}s'.format(secs // 60, secs % 60) if secs >= 60 else '{}s'.format(secs)

    def _spinner_thread():
        i = 0
        while not _spin_stop.is_set():
            if not _first_done.is_set():
                elapsed = time.monotonic() - t_start
                print('{clr}  {cy}{spin}{r} {n} worker(s) running… {d}{t} elapsed{r}'.format(
                    clr=CLR, cy=c.CYAN, spin=_SPIN[i % len(_SPIN)], r=c.RESET,
                    n=args.workers, d=c.DIM, t=_fmt_dur(elapsed)),
                    end='', file=sys.stderr, flush=True)
                i += 1
            time.sleep(0.4)

    def _domain_line(domain, perms, err):
        nonlocal tot_look, tot_mx, tot_park, tot_idn
        if err:
            return '  {red}✘  {dom:<{w}}{r}{d}{msg}{r}'.format(
                red=c.RED, r=c.RESET, dom=domain, w=DW, d=c.DIM, msg=err)
        look, mx, park, idn = perm_stats(perms)
        tot_look += look; tot_mx += mx; tot_park += park; tot_idn += idn
        head = '  {g}✔{r}  {cy}{b}{dom:<{w}}{r}'.format(
            g=c.GREEN, r=c.RESET, cy=c.CYAN, b=c.BOLD, dom=domain, w=DW)
        if args.no_dns:
            return head + '{b}{n:>5}{r} permutations'.format(b=c.BOLD, n=look, r=c.RESET)
        if look == 0:
            return head + '{d}no registered lookalike{r}'.format(d=c.GREY, r=c.RESET)
        mxc = c.RED if mx else c.GREY
        pkc = c.YELLOW if park else c.GREY
        return head + ('{b}{look:>4}{r} lookalikes   {mxc}{mx:>3}{r} {d}with mail server{r}'
                       '   {pkc}{park:>3}{r} {d}parked{r}').format(
            b=c.BOLD, r=c.RESET, look=look, mxc=mxc, mx=mx,
            pkc=pkc, park=park, d=c.DIM)

    try:
        work = [(d, build_scan_kwargs(d, args)) for d in remaining]

        with open(args.output, 'a', encoding='utf-8') as outf, \
             open(idx_path,     'a', encoding='utf-8') as idxf:

            t_start = time.monotonic()
            spinner = None
            if tty:
                spinner = threading.Thread(target=_spinner_thread, daemon=True)
                spinner.start()

            def _process_result(domain, perms, err):
                nonlocal n_scanned, n_errors
                _first_done.set()
                if err:
                    n_errors += 1
                offset = outf.tell()
                record = {'domain': domain, 'permutations': perms}
                outf.write(json.dumps(record, ensure_ascii=False, default=str) + '\n')
                outf.flush()
                idxf.write('{}\t{}\t{}\n'.format(domain, offset, len(perms)))
                idxf.flush()
                n_scanned += 1

                # one clean line per completed domain (clears the live status line)
                print(CLR + _domain_line(domain, perms, err), file=sys.stderr, flush=True)

                if tty:
                    elapsed = time.monotonic() - t_start
                    rate = n_scanned / elapsed if elapsed else 0
                    eta = (n_remaining - n_scanned) / rate if rate else 0
                    print('  {d}[{done}/{total}]  {rate:.1f}/s  ETA {eta}  ·  {err} error(s){r}'.format(
                        d=c.GREY, r=c.RESET, done=n_done + n_scanned, total=total_all,
                        rate=rate, eta=_fmt_dur(eta), err=n_errors),
                        end='', file=sys.stderr, flush=True)

            if args.workers > 1:
                chunksize = max(1, min(args.workers * 4, 64))
                with Pool(processes=args.workers, initializer=_worker_init) as pool:
                    try:
                        for domain, perms, err in pool.imap_unordered(
                                _scan_worker, work, chunksize=chunksize):
                            _process_result(domain, perms, err)
                    except KeyboardInterrupt:
                        pool.terminate()
                        print('{clr}\n  {y}Interrupted — progress saved. Re-run to resume.{r}'.format(
                            clr=CLR, y=c.YELLOW, r=c.RESET), file=sys.stderr)
            else:
                try:
                    for domain, kwargs in work:
                        try:
                            result = dnstwist.run(**kwargs)
                            perms = result if result is not None else []
                            _process_result(domain, perms, None)
                        except KeyboardInterrupt:
                            raise
                        except Exception as e:
                            _process_result(domain, [], str(e))
                except KeyboardInterrupt:
                    print('{clr}\n  {y}Interrompu — progression sauvegardée. Relancez pour reprendre.{r}'.format(
                        clr=CLR, y=c.YELLOW, r=c.RESET), file=sys.stderr)

            _spin_stop.set()

    except OSError as e:
        print('\nCannot write {}: {}'.format(args.output, e.strerror.lower()),
              file=sys.stderr)
        sys.exit(1)

    # ---- summary ----
    total_elapsed = time.monotonic() - t_start
    err_color = c.RED if n_errors else c.GREEN
    print(CLR, end='', file=sys.stderr)
    print(file=sys.stderr)
    print(bar, file=sys.stderr)
    print('  {b}Summary{r}  {d}· {t}{r}'.format(
        b=c.BOLD, r=c.RESET, d=c.DIM, t=_fmt_dur(total_elapsed)), file=sys.stderr)
    print('  {d}scanned   {r}: {b}{n}{r}/{rem}   {ec}{e} error(s){r}'.format(
        d=c.GREY, r=c.RESET, b=c.BOLD, n=n_scanned, rem=n_remaining,
        ec=err_color, e=n_errors), file=sys.stderr)
    if args.no_dns:
        print('  {d}permutations{r}: {b}{n}{r}'.format(
            d=c.GREY, r=c.RESET, b=c.BOLD, n=tot_look), file=sys.stderr)
    else:
        mail_label, park_label = 'with mail server (can receive e-mail)', 'parked (parking / resale)'
        w = max(len(mail_label), len(park_label))
        print('  {d}lookalikes{r}: {b}{n}{r}'.format(
            d=c.GREY, r=c.RESET, b=c.BOLD, n=tot_look), file=sys.stderr)
        print('      {d}├─ {lab:<{w}}{r} : {red}{n}{r}'.format(
            d=c.GREY, r=c.RESET, lab=mail_label, w=w, red=c.RED, n=tot_mx), file=sys.stderr)
        print('      {d}└─ {lab:<{w}}{r} : {y}{n}{r}'.format(
            d=c.GREY, r=c.RESET, lab=park_label, w=w, y=c.YELLOW, n=tot_park), file=sys.stderr)
    print('  {d}output    {r}: {out}  {d}(+ .idx){r}'.format(
        d=c.GREY, r=c.RESET, out=args.output), file=sys.stderr)
    print(bar, file=sys.stderr)


if __name__ == '__main__':
    main()
