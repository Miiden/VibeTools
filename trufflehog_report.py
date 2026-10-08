#!/usr/bin/env python3
"""Generate grouped, confidential Markdown and/or HTML TruffleHog reports."""

#=================================
# Vibed by Miiden
#=================================

import argparse
import html
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

GUIDANCE = {
    'aws': ('AWS access credentials', 'An exposed usable key may permit access to AWS resources within the associated IAM permissions.', 'Revoke or rotate the access key; review IAM permissions and CloudTrail logs.'),
    'github': ('GitHub authentication credential', 'A usable token could permit repository, workflow or organisation access within granted scopes.', 'Revoke the token and review its scopes and organisation audit events.'),
    'gitlab': ('GitLab authentication credential', 'A usable token may grant access to projects, pipelines or associated resources.', 'Revoke the token and review project permissions and audit events.'),
    'anypoint': ('MuleSoft Anypoint OAuth credential', 'A usable credential may grant access to Anypoint services within assigned permissions.', 'Rotate or revoke the affected OAuth credential; review client permissions and authentication logs.'),
    'slack': ('Slack authentication credential', 'A usable token might expose workspace data or permit scoped actions.', 'Revoke the token and inspect workspace audit activity.'),
    'privatekey': ('Private key material', 'An exposed private key could permit authentication or identity impersonation where trusted.', 'Replace the key pair and revoke affected certificates or authorisations.'),
    'stripe': ('Stripe API credential', 'A usable API key may permit access to payment-related services depending on assigned permissions.', 'Rotate the key and inspect Stripe API request logs.'),
    'oauth': ('OAuth credential', 'An exposed credential may permit access to an API within its delegated scope.', 'Revoke or rotate the credential and review sign-in or grant activity.'),
}
MISSING = {'', 'not provided', 'unknown detector', '[secret value not present in scan output]', 'null', 'none'}


def present(v):
    return v is not None and str(v).strip().lower() not in MISSING


def val(v, default='Not provided'):
    return str(v) if present(v) else default


def records_from(path):
    text = path.read_text(encoding='utf-8-sig')
    decoder = json.JSONDecoder()
    i = 0
    while i < len(text):
        while i < len(text) and (text[i].isspace() or text[i] == '\x1e'):
            i += 1
        if i >= len(text):
            break
        try:
            obj, i = decoder.raw_decode(text, i)
        except json.JSONDecodeError as exc:
            raise ValueError(f'Invalid input JSON at line {text.count(chr(10), 0, exc.pos)+1}: {exc.msg}') from exc
        for r in obj if isinstance(obj, list) else [obj]:
            if not isinstance(r, dict):
                raise ValueError('JSON input must contain objects')
            yield r


def extract(r, include_unverified):
    raw = 'SourceMetadata' in r or 'DetectorName' in r
    verified = r.get('Verified')
    if raw and verified is not True and not include_unverified:
        return None
    metadata = r.get('SourceMetadata') or {}
    data = metadata.get('Data') or {} if isinstance(metadata, dict) else {}
    git = data.get('Git') or {} if isinstance(data, dict) else {}
    if not isinstance(git, dict):
        git = {}
    def field(formatted, original):
        return r.get(formatted) if formatted in r else git.get(original)
    secret = r.get('Raw') or r.get('Secret') or r.get('RawV2')
    if isinstance(secret, (list, dict)):
        secret = json.dumps(secret, ensure_ascii=False)
    repo, file_, kind = field('Repository', 'repository'), field('File', 'file'), r.get('DetectorName') or r.get('Type')
    if not all(map(present, (repo, file_, kind, secret))):
        return None
    return dict(repository=str(repo), file=str(file_), type=str(kind), secret=str(secret),
                branch=val(field('Branch', 'branch'), 'Not determined'),
                commit=val(field('Commit', 'commit')), line=val(field('Line', 'line')),
                verified=verified)


def advice(detector):
    clean = re.sub('[^a-z0-9]', '', detector.lower())
    for key, advice_set in GUIDANCE.items():
        if key in clean:
            return advice_set
    return ('Potential authentication secret', 'If usable, an exposed secret might permit unauthorised access according to the service and granted permissions.', 'Identify the issuing service, revoke or rotate the credential, and review relevant audit logs.')


def group(findings):
    byfile = {}
    for f in findings:
        k = (f['repository'], f['file'])
        entry = byfile.setdefault(k, {'repository': f['repository'], 'file': f['file'], 'credentials': {}})
        c = entry['credentials'].setdefault((f['type'], f['secret']), {'type': f['type'], 'secret': f['secret'], 'occurrences': [], '_seen': set()})
        occurrence = (f['commit'], f['branch'], f['line'], f['verified'])
        if occurrence not in c['_seen']:
            c['occurrences'].append({'commit': f['commit'], 'branch': f['branch'], 'line': f['line'], 'verified': f['verified']})
            c['_seen'].add(occurrence)
    grouped = sorted(byfile.values(), key=lambda x: (x['repository'].lower(), x['file'].lower()))
    for item in grouped:
        item['credentials'] = sorted(item['credentials'].values(), key=lambda x: (x['type'].lower(), x['secret']))
        for c in item['credentials']:
            del c['_seen']
            c['occurrences'].sort(key=lambda x: (x['commit'], x['line']))
    return grouped


def summary(groups, total, included):
    return dict(total=total, included=included, files=len(groups), repos=len({g['repository'] for g in groups}),
                secrets=sum(len(g['credentials']) for g in groups),
                occurrences=sum(len(c['occurrences']) for g in groups for c in g['credentials']),
                counts=Counter(c['type'] for g in groups for c in g['credentials']))


def status(v):
    return 'Verified by TruffleHog at scan time' if v is True else 'Unverified by TruffleHog' if v is False else 'Verification status not supplied'


def md(v):
    return (str(v).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            .replace('|', '&#124;').replace('`', '&#96;').replace('\\', '&#92;')
            .replace('\r', '').replace('\n', '&#10;'))


def markdown(groups, stats):
    out = ['# Credential Exposure Assessment — TruffleHog Results', '',
           '**CONFIDENTIAL — FULL CREDENTIAL VALUES INCLUDED.** Share only through an approved secure channel.', '',
           '## Executive summary', '',
           f"Processed **{stats['total']}** records; included **{stats['included']}** valid detection records across **{stats['repos']}** repositories and **{stats['files']}** affected files.", '',
           f"**{stats['secrets']} distinct credentials** and **{stats['occurrences']} recorded commit/line occurrences** are represented below.", '',
           'Verification reflects the scanner output at scan time; severity and business impact require further assessment. This is not proof of comprehensive Git history coverage.', '',
           '## Detector overview', '', '| Detector | Distinct credentials |', '| --- | ---: |']
    out += [f'| {md(k)} | {n} |' for k,n in sorted(stats['counts'].items())]
    out += ['', '## Detailed findings', '']
    if not groups:
        out += ['No matching findings were present in the supplied results. This does not demonstrate absence of secrets.', '']
    for n, g in enumerate(groups, 1):
        out += [f'### Finding {n} — {md(g["file"])}', '',
                f'**Repository:** `{md(g["repository"])}`', '',
                '**Description**', '',
                f'TruffleHog identified {len(g["credentials"])} distinct credential(s) in `{md(g["file"])}`. The occurrences below identify affected commits and available branch metadata. A commit can be present on multiple branches.', '']
        for j,c in enumerate(g['credentials'],1):
            label,impact,remedy=advice(c['type'])
            out += [f'#### Credential {j}: {md(label)} — {md(c["type"])}', '',
                    '**Full exposed credential (sensitive):**', '', f'`{md(c["secret"])}`', '',
                    '| Commit | Branch | Line | Validation |', '| --- | --- | ---: | --- |']
            out += [f'| {md(o["commit"])} | {md(o["branch"])} | {md(o["line"])} | {status(o["verified"])} |' for o in c['occurrences']]
            out += ['', '**Potential impact:** '+impact, '',
                    '**Remediation:** '+remedy+' Remove the credential from tracked configuration and use a suitable secrets manager or protected CI/CD variable. Rewriting Git history does not invalidate a credential.', '',
                    '**Retest:** Confirm that the original credential is revoked, review relevant service activity and rerun scanning after remediation.', '']
        out += ['---', '']
    out += ['## Overall recommendations', '',
            '1. Revoke or rotate exposed credentials, prioritising confirmed usable and high-privilege material.',
            '2. Investigate access and relevant service audit logs.',
            '3. Use protected secret storage instead of hardcoded credentials.',
            '4. Rescan and validate remediation.', '',
            '**Assessment note:** Detection alone does not establish exploitability, misuse or a specific severity.', '']
    return '\n'.join(out)


def h(v):
    return html.escape(str(v), quote=True)


def html_report(groups, stats):
    css = '''
:root{color-scheme:light;--ink:#18263b;--muted:#5a6980;--navy:#10243a;--blue:#1660a8;--line:#dae3ed;--bg:#f3f6fa;--white:white}
*{box-sizing:border-box}body{margin:0;background:var(--bg);font:15px/1.6 system-ui,-apple-system,Segoe UI,sans-serif;color:var(--ink)}
header{background:var(--navy);color:white;padding:40px max(24px,calc((100vw - 1100px)/2))}header h1{font-size:30px;line-height:1.2;margin:6px 0 10px}header p{color:#c9d5e4;margin:0}.eyebrow{font-size:12px;letter-spacing:.16em;text-transform:uppercase;font-weight:700;color:#9fc1e8}
main{max-width:1100px;margin:auto;padding:28px 24px 80px}.notice{border-left:5px solid #b45309;background:#fff7eb;padding:16px 20px;margin-bottom:28px;border-radius:4px}
.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.metric,.panel,.finding{background:white;border:1px solid var(--line);border-radius:10px;box-shadow:0 2px 10px #15283e09}.metric{padding:19px}.metric strong{font-size:28px;display:block;color:var(--navy)}.metric span{font-size:12px;color:var(--muted)}
h2{font-size:22px;margin:38px 0 15px}h3{font-size:19px;margin:0}h4{font-size:16px;margin:0 0 9px}.panel{padding:24px}.muted{color:var(--muted)}table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid var(--line);padding:10px 12px;text-align:left;vertical-align:top;word-break:break-word}th{background:#ecf2f8;color:#2a415c}.table-wrap{overflow-x:auto}.finding{margin:25px 0;overflow:hidden}.finding-heading{padding:22px 26px;background:#f8fbff;border-bottom:1px solid var(--line)}.finding-body{padding:24px 26px}.credential{border-top:1px solid var(--line);margin-top:26px;padding-top:22px}.tag{display:inline-block;background:#e6f0fc;color:#15538e;border-radius:12px;padding:2px 9px;font-size:12px;font-weight:700;margin-top:8px}.secret{background:#fff7e6;border:1px solid #edd39a;border-radius:6px;padding:12px;white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace}.text-label{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-weight:700;margin:16px 0 6px}code{overflow-wrap:anywhere}footer{font-size:12px;color:var(--muted);margin-top:38px}a{color:var(--blue)}
@media(max-width:680px){.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}header{padding:32px 22px}.finding-heading,.finding-body{padding:19px}main{padding:20px 14px}}
@media print{body{background:white}header{print-color-adjust:exact;-webkit-print-color-adjust:exact}.finding,.panel,.metric{box-shadow:none}.credential{break-inside:avoid}.finding{break-inside:auto}main{padding:12px}a{color:inherit}}
'''
    content = [f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Credential Exposure Assessment — TruffleHog</title><style>{css}</style></head><body>
<header><div class="eyebrow">Security assessment / confidential</div><h1>Credential Exposure Assessment</h1><p>TruffleHog scan results · Report prepared {h(datetime.now(timezone.utc).strftime('%d %B %Y, %H:%M UTC'))}</p></header>
<main><div class="notice"><strong>Confidential — full credential values included.</strong> This report contains sensitive evidence. Restrict access, store securely and deliver only through approved channels.</div>
<section><h2>Executive summary</h2><div class="metrics">
<div class="metric"><strong>{stats['repos']}</strong><span>Affected repositories</span></div><div class="metric"><strong>{stats['files']}</strong><span>Affected files / findings</span></div><div class="metric"><strong>{stats['secrets']}</strong><span>Distinct credentials</span></div><div class="metric"><strong>{stats['occurrences']}</strong><span>Recorded occurrences</span></div></div>
<p>Of <strong>{stats['total']}</strong> input records, <strong>{stats['included']}</strong> valid detection records were included. Counts describe supplied scanner output, not full coverage of all Git history.</p>
<p class="muted">TruffleHog verification reflects scanner status at the time of the scan; it does not establish current usability, misuse or business severity.</p></section>
<section><h2>Detector overview</h2><div class="panel table-wrap"><table><thead><tr><th>Detector</th><th>Distinct credentials</th></tr></thead><tbody>''']
    content.extend(f'<tr><td>{h(k)}</td><td>{v}</td></tr>' for k,v in sorted(stats['counts'].items()))
    content.append('</tbody></table></div></section><section><h2>Detailed findings</h2>')
    if not groups:
        content.append('<div class="panel">No matching findings were present in the supplied results. This does not demonstrate absence of secrets.</div>')
    for n, g in enumerate(groups,1):
        content.append(f'<article class="finding"><div class="finding-heading"><div class="eyebrow" style="color:#526885">Finding {n:03d}</div><h3>{h(g["file"])}</h3><div class="muted">Repository: <code>{h(g["repository"])}</code></div><span class="tag">{len(g["credentials"])} distinct credential(s)</span></div><div class="finding-body"><h4>Description</h4><p>TruffleHog identified credential material in this file across the recorded Git revisions. Details below preserve the full credential value, detected type and affected commits. Branch metadata may be unavailable or may represent multiple branches containing the same commit.</p>')
        for j,c in enumerate(g['credentials'],1):
            label,impact,remedy=advice(c['type'])
            content.append(f'<section class="credential"><h4>Credential {j}: {h(label)}</h4><p class="muted">Detector: <strong>{h(c["type"])}</strong></p><div class="text-label">Full exposed credential — sensitive</div><div class="secret">{h(c["secret"])}</div><div class="text-label">Affected commits and locations</div><div class="table-wrap"><table><thead><tr><th>Commit</th><th>Branch</th><th>Line</th><th>Validation</th></tr></thead><tbody>')
            for o in c['occurrences']:
                content.append(f'<tr><td><code>{h(o["commit"])}</code></td><td>{h(o["branch"])}</td><td>{h(o["line"])}</td><td>{h(status(o["verified"]))}</td></tr>')
            content.append(f'</tbody></table></div><div class="text-label">Potential impact</div><p>{h(impact)}</p><div class="text-label">Recommended remediation</div><p>{h(remedy)} Remove credentials from tracked configuration and replace with a secrets manager or protected CI/CD variable. Git history rewriting alone does not invalidate a credential.</p><div class="text-label">Validation / retest</div><p>Confirm the original secret is revoked or unusable, investigate relevant audit logs and rerun scanning after remediation.</p></section>')
        content.append('</div></article>')
    content.append('''</section><section><h2>Overall recommendations</h2><div class="panel"><ol><li>Revoke or rotate exposed credentials, prioritising verified and privileged material.</li><li>Review associated access and relevant audit logs.</li><li>Use a secrets manager or protected CI/CD secrets storage instead of hardcoding keys.</li><li>Rescan and validate remediation.</li></ol><p class="muted">Severity and evidence of misuse require a separate customer-specific assessment.</p></div></section><footer>Confidential customer security assessment · Generated from supplied TruffleHog records.</footer></main></body></html>''')
    return ''.join(content)


def secure_write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == 'posix':
        fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            f.write(content)
    else:
        path.write_text(content,encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input',type=Path,help='Raw TruffleHog JSONL, JSON array or formatted JSON objects')
    parser.add_argument('--format',choices=['md','html','both'],default='md',help='Output format (default: md)')
    parser.add_argument('-o','--output',type=Path,help='Output filename (single format) or basename (both)')
    parser.add_argument('--include-unverified',action='store_true',help='Include unverified/unknown raw TruffleHog findings')
    args = parser.parse_args()
    base = args.output or args.input.with_name(args.input.stem+'_report')
    dests = ([base.with_suffix('.md'),base.with_suffix('.html')] if args.format == 'both' else
             [base if base.suffix.lower() == '.'+args.format else base.with_suffix('.'+args.format)])
    try:
        if any(p.resolve() == args.input.resolve() for p in dests):
            raise ValueError('Input and output paths must be different')
        records = list(records_from(args.input))
        findings = [f for r in records if (f:=extract(r,args.include_unverified)) is not None]
        groups = group(findings)
        stats = summary(groups,len(records),len(findings))
        for dest in dests:
            secure_write(dest, html_report(groups,stats) if dest.suffix=='.html' else markdown(groups,stats))
            print(f'Confidential report written to: {dest}')
    except (OSError,ValueError,TypeError,AttributeError) as exc:
        parser.exit(1,f'Error: {exc}\n')
    print(f"Records: {stats['total']} | Valid: {stats['included']} | Files: {stats['files']} | Distinct secrets: {stats['secrets']}")
    print('WARNING: Reports contain full credentials. Restrict access and transfer securely.')

if __name__ == '__main__':
    main()
