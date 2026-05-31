#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Batch wrapper around dnstwist: reads domains from a CSV file (one per line),
runs the full dnstwist scan for each, and writes results in JSON Lines format.

Output format (one JSON object per line):
  {"domain": "google.com", "permutations": [...]}
  {"domain": "github.com", "permutations": [...]}

Resume behaviour: if the output file already exists, domains already present
in it are skipped automatically. Delete the file to start from scratch.
'''

import csv
import json
import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dnstwist


def read_domains(filepath):
    '''Read domains from CSV. Accepts plain-domain CSVs and rank,domain (Tranco) format.'''
    domains = []
    with open(filepath, encoding='utf-8') as f:
        for row in csv.reader(f):
            if not row:
                continue
            # Use last column; handles both "domain" and "rank,domain" layouts.
            domain = row[-1].strip()
            if domain and not domain.startswith('#') and not domain.isdigit():
                domains.append(domain)
    return domains


def load_done_domains(filepath):
    '''Return the set of domains already present in an existing JSONL output file.'''
    done = set()
    if not os.path.exists(filepath):
        return done
    with open(filepath, encoding='utf-8') as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if 'domain' in obj:
                    done.add(obj['domain'])
            except json.JSONDecodeError:
                print('WARNING: skipping malformed line {} in {}'.format(lineno, filepath),
                      file=sys.stderr)
    return done


def scan_domain(domain, args):
    kwargs = {
        'domain': domain,
        'output': dnstwist.devnull,
    }
    if getattr(args, 'no_dns', False):
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
    if not getattr(args, 'no_dns', False) and args.threads:
        kwargs['threads'] = args.threads
    if args.whois:
        kwargs['whois'] = True
    if args.tld:
        kwargs['tld'] = args.tld
    if args.nameservers:
        kwargs['nameservers'] = args.nameservers
    if args.useragent:
        kwargs['useragent'] = args.useragent
    return dnstwist.run(**kwargs)


def main():
    parser = argparse.ArgumentParser(
        prog=os.path.basename(sys.argv[0]),
        description='Batch dnstwist scanner — reads domains from CSV, writes JSONL',
        epilog='Output is JSON Lines (one record per domain). Re-running resumes automatically.',
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=30),
    )
    parser.add_argument('input', metavar='CSV', help='Input CSV file (one domain per line)')
    parser.add_argument('-o', '--output', metavar='FILE', required=True,
        help='Output file (appended to if it already exists; use --json for a proper JSON array)')
    parser.add_argument('--no-dns', action='store_true',
        help='Skip DNS resolution — generate permutations only (much faster)')
    parser.add_argument('--json', action='store_true',
        help='Write a single JSON array instead of JSON Lines (JSONL)')

    # dnstwist options
    parser.add_argument('-a', '--all', action='store_true', help='Include all DNS records instead of the first ones')
    parser.add_argument('-b', '--banners', action='store_true', help='Fetch HTTP and SMTP service banners')
    parser.add_argument('-d', '--dictionary', metavar='FILE', help='Extra permutations from dictionary FILE')
    parser.add_argument('--fuzzers', metavar='LIST', help='Comma-separated list of fuzzers to use')
    parser.add_argument('-g', '--geoip', action='store_true', help='GeoIP country lookup')
    parser.add_argument('--lsh', metavar='ALGO', nargs='?', const='ssdeep', choices=['ssdeep', 'tlsh'],
        help='HTML similarity algorithm: ssdeep, tlsh (default: ssdeep)')
    parser.add_argument('--lsh-url', metavar='URL', help='Override URL for LSH reference page')
    parser.add_argument('-m', '--mxcheck', action='store_true', help='Check MX for email interception')
    parser.add_argument('-r', '--registered', action='store_true', help='Only registered domains in output')
    parser.add_argument('-u', '--unregistered', action='store_true', help='Only unregistered domains in output')
    parser.add_argument('-t', '--threads', type=int, metavar='NUM', default=dnstwist.THREAD_COUNT_DEFAULT,
        help='Scanner threads per domain (default: %d)' % dnstwist.THREAD_COUNT_DEFAULT)
    parser.add_argument('-w', '--whois', action='store_true', help='WHOIS lookup (registrar + creation date)')
    parser.add_argument('--tld', metavar='FILE', help='TLD swap dictionary file')
    parser.add_argument('--nameservers', metavar='LIST', help='DNS/DoH servers to query (comma-separated)')
    parser.add_argument('--useragent', metavar='STRING', default=dnstwist.USER_AGENT_STRING,
        help='User-Agent string for HTTP requests')

    args = parser.parse_args()

    if args.registered and args.unregistered:
        parser.error('--registered and --unregistered are mutually exclusive')
    if args.lsh_url and not args.lsh:
        parser.error('--lsh-url requires --lsh')
    if args.no_dns and (args.registered or args.unregistered or args.banners or
                        args.geoip or args.lsh or args.mxcheck or args.whois):
        parser.error('--no-dns is incompatible with DNS-dependent options')

    try:
        all_domains = read_domains(args.input)
    except OSError as e:
        parser.error('cannot open {}: {}'.format(args.input, e.strerror.lower()))

    if not all_domains:
        parser.error('no domains found in {}'.format(args.input))

    # Resume: skip domains already present in the output file
    done_domains = load_done_domains(args.output)
    remaining = [d for d in all_domains if d not in done_domains]

    total_all = len(all_domains)
    n_done = len(done_domains)
    n_remaining = len(remaining)

    if n_done:
        print('Resuming: {}/{} domain(s) already scanned, {} remaining.'.format(
            n_done, total_all, n_remaining), file=sys.stderr)
    else:
        print('Loaded {} domain(s) from {}'.format(total_all, args.input), file=sys.stderr)

    if not remaining:
        print('All domains already scanned. Nothing to do.', file=sys.stderr)
        return

    n_scanned = 0
    n_errors = 0

    if args.json:
        records = []
        for i, domain in enumerate(remaining, 1):
            overall = n_done + i
            print('[{}/{}] Processing {} ...'.format(overall, total_all, domain),
                  file=sys.stderr, flush=True)
            try:
                data = scan_domain(domain, args)
                permutations = data if data is not None else []
            except KeyboardInterrupt:
                print('\nInterrupted.', file=sys.stderr)
                break
            except Exception as e:
                print('  ERROR: {}'.format(e), file=sys.stderr)
                permutations = []
                n_errors += 1
            records.append({'domain': domain, 'permutations': permutations})
            n_scanned += 1
        try:
            with open(args.output, 'w', encoding='utf-8') as outf:
                json.dump(records, outf, ensure_ascii=False, default=str, indent=2)
                outf.write('\n')
        except OSError as e:
            print('Cannot write {}: {}'.format(args.output, e.strerror.lower()), file=sys.stderr)
            sys.exit(1)
    else:
        try:
            # Append mode so previous results are preserved on resume
            with open(args.output, 'a', encoding='utf-8') as outf:
                for i, domain in enumerate(remaining, 1):
                    overall = n_done + i
                    print('[{}/{}] Processing {} ...'.format(overall, total_all, domain),
                          file=sys.stderr, flush=True)
                    try:
                        data = scan_domain(domain, args)
                        permutations = data if data is not None else []
                    except KeyboardInterrupt:
                        print('\nInterrupted — progress saved. Re-run to resume.', file=sys.stderr)
                        break
                    except Exception as e:
                        print('  ERROR: {}'.format(e), file=sys.stderr)
                        permutations = []
                        n_errors += 1

                    record = {'domain': domain, 'permutations': permutations}
                    outf.write(json.dumps(record, ensure_ascii=False, default=str) + '\n')
                    outf.flush()
                    n_scanned += 1

        except OSError as e:
            print('Cannot write {}: {}'.format(args.output, e.strerror.lower()), file=sys.stderr)
            sys.exit(1)

    print(
        'Done. {}/{} domain(s) scanned this run ({} error(s)). Output: {}'.format(
            n_scanned, n_remaining, n_errors, args.output
        ),
        file=sys.stderr,
    )


if __name__ == '__main__':
    main()
