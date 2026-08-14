# AI Security Data Processing Engine

Week 2 mini project that combines threat-data ingestion, log enrichment, risk scoring, anomaly detection, API security concepts, and backend dashboard logic.

## Features

- **Log ingestion:** reads JSON logs from `sample_raw_logs.json`.
- **Threat enrichment:** identifies suspicious IPs, unknown domains/IOCs, GeoIP country/region, and device type.
- **Risk scoring:** suspicious IP = +3, unknown domain = +2, repeated activity = +4.
- **Anomaly detection:** detects unusual login hours, repeated failed access, and an IP used across multiple accounts.
- **Backend logic:** stores enriched logs, filters them by severity, and returns the top 10 threats.
- **API security:** contains an API-key validation and basic rate-limiting simulation for protected ingestion.
- **Report generation:** saves all results to `security_report.json`.

## Internship topics used

- OOP: `SecureAPIService`, `ThreatFeedClient`, `LogEnricher`, `RiskScorer`, `AnomalyDetector`, and `SOCDashboardBackend` classes.
- JSON and file handling: input, mock threat intelligence, and final output all use JSON files.
- REST API / `requests`: by default, the project uses the mock threat feed. Set `THREAT_API_URL` to an authorized JSON API to fetch a live feed using `requests`.

## Run

Open a terminal in this project folder and run:

```powershell
pip install -r requirements.txt
python main.py
```

`security_report.json` will be created in the same folder.

## Input files

- `sample_raw_logs.json` — source activity/log data.
- `threat_intelligence.json` — mock feed containing suspicious IPs, known domains, and GeoIP records.

## Output

`sample_security_report.json` is an example output included with the project. Running the script creates the full `security_report.json`, which includes:

- report summary
- enriched logs
- top 10 threats, ordered by risk score
- anomaly alerts

## Notes

The IP addresses and data are documentation-only sample values. This is a learning project, not a production SOC platform. Use authorized APIs only, do not store real API keys in source files, and use a secrets manager and shared rate-limit storage in production.
