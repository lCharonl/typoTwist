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

    if n_done:
        print('Resuming: {}/{} domain(s) already done, {} remaining.'.format(
            n_done, total_all, n_remaining), file=sys.stderr)
    else:
        print('Loaded {} domain(s) from {}'.format(total_all, args.input), file=sys.stderr)

    if args.workers > 1:
        print('Workers: {} parallel processes'.format(args.workers), file=sys.stderr)

    if not remaining:
        print('All domains already processed. Nothing to do.', file=sys.stderr)
        return

    n_scanned = 0
    n_errors = 0
    idx_path = args.output + '.idx'

    _SPIN = '|/-\\'
    _spin_stop  = threading.Event()
    _first_done = threading.Event()

    def _spinner_thread():
        i = 0
        while not _spin_stop.is_set():
            if not _first_done.is_set():
                elapsed = time.monotonic() - t_start
                print('\r{} workers active... {:.0f}s elapsed   '.format(
                    args.workers, elapsed) if args.workers > 1 else
                      '\r{} working... {:.0f}s elapsed   '.format(
                    _SPIN[i % 4], elapsed),
                    end='', file=sys.stderr, flush=True)
                i += 1
            time.sleep(0.4)

    try:
        work = [(d, build_scan_kwargs(d, args)) for d in remaining]

        with open(args.output, 'a', encoding='utf-8') as outf, \
             open(idx_path,     'a', encoding='utf-8') as idxf:

            t_start = time.monotonic()
            spinner = threading.Thread(target=_spinner_thread, daemon=True)
            spinner.start()

            def _process_result(domain, perms, err):
                nonlocal n_scanned, n_errors
                _first_done.set()
                if err:
                    print('\n  ERROR {}: {}'.format(domain, err), file=sys.stderr)
                    n_errors += 1
                offset = outf.tell()
                record = {'domain': domain, 'permutations': perms}
                outf.write(json.dumps(record, ensure_ascii=False, default=str) + '\n')
                outf.flush()
                idxf.write('{}\t{}\t{}\n'.format(domain, offset, len(perms)))
                idxf.flush()
                n_scanned += 1
                elapsed = time.monotonic() - t_start
                rate = n_scanned / elapsed if elapsed else 0
                eta = (n_remaining - n_scanned) / rate if rate else 0
                print('\r[{}/{}] {:.1f}/s  ETA {:.0f}m{:02.0f}s  errors: {}   '.format(
                    n_done + n_scanned, total_all,
                    rate, eta // 60, eta % 60, n_errors),
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
                        print('\nInterrupted — progress saved. Re-run to resume.',
                              file=sys.stderr)
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
                    print('\nInterrupted — progress saved. Re-run to resume.',
                          file=sys.stderr)

            _spin_stop.set()

    except OSError as e:
        print('\nCannot write {}: {}'.format(args.output, e.strerror.lower()),
              file=sys.stderr)
        sys.exit(1)

    print('\nDone. {}/{} processed this run ({} error(s)).'.format(
        n_scanned, n_remaining, n_errors), file=sys.stderr)
    print('Output : {}'.format(args.output), file=sys.stderr)
    print('Index  : {}'.format(idx_path), file=sys.stderr)


if __name__ == '__main__':
    main()
