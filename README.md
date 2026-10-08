# VibeTools




## TruffleHog Report Generator - trufflehog_report.py

A lightweight Python reporting tool that converts raw TruffleHog JSON/JSONL scan results into professional, customer-readable security reports in **HTML and Markdown** formats.

The tool processes detected credential exposures across Git repositories, including historical commits and branches, consolidating duplicate findings into a structured report suitable for security assessments and penetration testing engagements.

### Features
- **Raw TruffleHog Support:** Processes JSON/JSONL results directly without additional formatting or preprocessing.
- **Multiple Export Formats:** Generates standalone HTML reports, Markdown reports, or both.
- **Finding Consolidation:** Groups findings by repository and file, combining duplicate credentials while preserving affected commits and line numbers.
- **Finding Validation:** Filters empty or incomplete results and distinguishes verified, unverified and unknown verification statuses.
- **Full Evidence Retention:** Preserves exposed credential values, repository information, commit hashes and file locations.
- **Professional Reporting:** Generates executive summaries, finding descriptions, potential security impacts and remediation recommendations.
- **Portable:** Uses Python 3's standard library with no additional dependencies.

### Usage

Generate a Markdown report (default):

```bash
python3 trufflehog_report.py trufflehog_results.jsonl
```

Generate an HTML report:

```bash
python3 trufflehog_report.py trufflehog_results.jsonl --format html
```

Generate both formats, including unverified findings:

```bash
python3 trufflehog_report.py trufflehog_results.jsonl --format both --include-unverified
```

### Security Notice

Generated reports contain full credential values and potentially sensitive repository information. Treat all output files as **confidential security evidence** and store, handle and distribute them securely.

**Note:** TruffleHog verification reflects credential status at scan time and does not guarantee continued validity or establish the severity of a finding.
