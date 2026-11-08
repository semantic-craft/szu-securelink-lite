#!/usr/bin/env python3
"""Read-only RSS accounting. Never launches or controls SecureLink."""
import argparse
import datetime
import json
from pathlib import Path
import subprocess


def summarize(text, app):
    app = str(Path(app)).rstrip('/') + '/'
    rows = []
    for line in text.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) != 3 or not parts[2].startswith(app):
            continue
        pid, rss, command = parts
        if not pid.isdecimal() or not rss.isdecimal():
            raise ValueError('Malformed selected process row')
        native = '/assets/app-ext/securelink_mac/' in command
        rows.append(dict(pid=int(pid), rss_kib=int(rss),
                         group='native' if native else 'electron', executable=command))
    totals = {group: sum(r['rss_kib'] for r in rows if r['group'] == group)
              for group in ('electron', 'native')}
    return dict(metric='RSS_KiB', process_count=len(rows), totals_kib=totals,
                total_kib=sum(totals.values()), processes=rows,
                limitation='RSS can double-count shared pages; not physical footprint. '
                'An empty list does not prove service absence or connectivity.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--app', required=True, help='Exact installed SecureLink.app path')
    parser.add_argument('--snapshot', type=Path, help='Parse a saved ps snapshot, fully offline')
    args = parser.parse_args()
    text = args.snapshot.read_text() if args.snapshot else subprocess.run(
        ['/bin/ps', '-axo', 'pid,rss,comm'], check=True, capture_output=True, text=True).stdout
    report = summarize(text, args.app)
    report['report_generated_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report['source'] = 'saved-snapshot' if args.snapshot else 'live-ps'
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
