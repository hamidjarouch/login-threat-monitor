# Login Threat Monitor

A local authentication-log investigation dashboard with explainable rules, event evidence and downloadable reports. Python standard library backend; HTML/CSS/JavaScript interface. No third-party packages, API keys or subscriptions.

## Start on Windows

1. Extract the entire ZIP (right-click → Extract All). Do not run inside the ZIP.
2. Open the extracted project folder.
3. Double-click `START_WINDOWS.bat`. Keep its console window open.
4. The browser opens automatically. Click **Load demo investigation**.
5. If the browser does not open, copy the `http://127.0.0.1:...` address from the console.
6. To stop, close the console or press Ctrl+C.

The launcher first checks the Python 3.14 path used on this computer, then `py -3`, then `python`. Fallback: open `app.py` in VS Code, choose your Python interpreter, and **Run Python File in Terminal**.

Mac/Linux: run `python3 app.py`. Python 3.10+ required. No pip commands needed.

## Demo and acceptance criteria

The supplied `sample.csv` contains 12 synthetic events, 9 failures and 3 source IPs. Default settings (3 failures / 5 minutes) produce 4 alerts:

- 10:04 — BURST on 192.0.2.10.
- 10:05 — SUCCESS_AFTER_FAILURES for admin on 192.0.2.10.
- 10:12 — BURST on 198.51.100.8.
- 10:12 — MULTI_ACCOUNT on 198.51.100.8, targeting alice, bob and carol.
- No alerts for 192.0.2.20: its failed logins are one hour apart.

Click each alert to inspect the original CSV row numbers and supporting events. Filter severity, search the event ledger, export CSV or JSON, or use Print report / PDF. Printing captures the current dashboard view and selected evidence; JSON is the complete report. The ledger displays at most 500 matching rows; the analyzer accepts up to 20,000 events. Sample IPs are documentation addresses.

## CSV format

```csv
timestamp,user,ip,status
2026-11-17 10:00:00,admin,192.0.2.10,failed
2026-11-17 10:01:00,admin,192.0.2.10,success
```

Required headers are exact. Additional columns are ignored. UTF-8 with or without BOM, comma-separated. Times must use `YYYY-MM-DD HH:MM:SS` and one consistent timezone. IPv4 and IPv6 accepted and normalized. Status must be `failed` or `success`. Invalid rows reject the entire import with a row-specific error; none are silently discarded. Events are sorted chronologically, preserving CSV order for equal timestamps. Duplicates count separately; deduplicate at source if appropriate.

## Rules and semantics

| Rule | Grouping | Trigger | Severity |
|---|---|---|---|
| BURST | Source IP | At least N failures in W minutes | Medium |
| SUCCESS_AFTER_FAILURES | Source IP + username | Success after at least N failures in W minutes, since the previous success | High |
| MULTI_ACCOUNT | Source IP | Failures for at least N distinct usernames in W minutes | Medium |

Window boundaries are inclusive. Defaults: N=3, W=5. Success clears the account sequence, not the IP's failure history. BURST and MULTI_ACCOUNT emit at threshold crossing and re-arm after the count falls below threshold. Settings reset on reload; all state is per analysis run. Overlapping rules can produce different alerts for the same event. Rule 1's user is the threshold-triggering user, not necessarily the only target. Evidence is captured when the alert fires, not extended by future events. Evidence count on success includes the successful event.

## Design

`CSV → validate → parse timestamps → sort → sliding windows → alerts → dashboard / exports`

- `detector.py`: independent validation and detection engine.
- `app.py`: local HTTP server, input size limit, per-run request token.
- `web/index.html`: dashboard layout.
- `web/style.css`: responsive dark theme and print styling.
- `web/app.js`: file upload, API calls, filters and report downloads.
- `test_detector.py`: automated checks for rule correctness and invalid input.
- `GUIDE_RU.md`: explanation and practice tasks in Russian.

## Tests

From this folder: `python -m unittest -v` (or `py -3 -m unittest -v`).

## Scope and limitations

This is an offline CSV portfolio lab, not a production SIEM or live monitoring agent. It does not scan networks, connect to the listed IPs, block traffic, collect credentials or prove account compromise. Shared NAT, human mistakes and automated services can cause false positives. Distributed attacks, unfamiliar successful logins and activity outside these three rules may be missed.

Files are processed in memory on your computer. The server binds only to 127.0.0.1; no external assets or telemetry are used. Exports are saved only when requested. Do not expose this development server to the internet. Use synthetic or anonymized records for public demonstrations. Report CSV cells are protected against common spreadsheet formula prefixes. The UI inserts log content as text rather than HTML.

## Portfolio description

Login Threat Monitor is a Python dashboard for investigating authentication events. It applies three configurable time-window rules, displays supporting evidence, and exports findings as CSV and JSON. The project demonstrates log parsing, validation, chronological processing, detection engineering and investigation reporting using a reproducible synthetic dataset.
