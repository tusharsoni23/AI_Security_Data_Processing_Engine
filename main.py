"""AI Security Data Processing Engine - Week 2 mini project.

Run: python main.py
Optional REST-style ingestion: set THREAT_API_URL to an authorized JSON API.
"""

import hmac
import json
import os
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta


INPUT_FILE = "sample_raw_logs.json"
THREAT_INTELLIGENCE_FILE = "threat_intelligence.json"
REPORT_FILE = "security_report.json"
API_KEY_ENVIRONMENT_NAME = "SOC_DEMO_API_KEY"


class SecureAPIService:
    """Small API-key and rate-limit simulation for protected log ingestion."""

    def __init__(self, valid_api_key, limit=5, window_seconds=60):
        self.valid_api_key = valid_api_key
        self.limit = limit
        self.window_seconds = window_seconds
        self.client_requests = defaultdict(deque)

    def allow_request(self, client_id, api_key, request_time):
        if not self.valid_api_key or not hmac.compare_digest(api_key or "", self.valid_api_key):
            return False, "401: invalid API key"

        requests = self.client_requests[client_id]
        while requests and request_time - requests[0] >= timedelta(seconds=self.window_seconds):
            requests.popleft()
        if len(requests) >= self.limit:
            return False, "429: rate limit exceeded"

        requests.append(request_time)
        return True, "200: request accepted"


class ThreatFeedClient:
    """Loads a mock feed, or optionally retrieves an authorized JSON REST feed."""

    @staticmethod
    def load_json(file_name):
        with open(file_name, "r", encoding="utf-8") as file:
            return json.load(file)

    def get_threat_data(self):
        api_url = os.getenv("THREAT_API_URL")
        if not api_url:
            return self.load_json(THREAT_INTELLIGENCE_FILE)

        # requests is used only when an authorized API URL is supplied.
        import requests
        response = requests.get(api_url, timeout=10)
        response.raise_for_status()
        return response.json()


class LogEnricher:
    def __init__(self, threat_data):
        self.suspicious_ips = set(threat_data["suspicious_ips"])
        self.known_domains = set(threat_data["known_domains"])
        self.geoip_data = threat_data["geoip_data"]

    def get_device_type(self, user_agent):
        agent = user_agent.lower()
        if "mobile" in agent or "android" in agent or "iphone" in agent:
            return "Mobile"
        if "curl" in agent or "python" in agent or "postman" in agent:
            return "API Client"
        return "Desktop"

    def enrich(self, log):
        enriched_log = log.copy()
        ip_address = log["ip_address"]
        location = self.geoip_data.get(ip_address, {"country": "Unknown", "region": "Unknown"})
        enriched_log["country"] = location["country"]
        enriched_log["region"] = location["region"]
        enriched_log["device_type"] = self.get_device_type(log["user_agent"])
        enriched_log["suspicious_ip"] = ip_address in self.suspicious_ips
        enriched_log["unknown_domain"] = log["domain"] not in self.known_domains
        enriched_log["ioc"] = ip_address if enriched_log["suspicious_ip"] else (log["domain"] if enriched_log["unknown_domain"] else None)
        return enriched_log


class RiskScorer:
    """Implements the Day 10 scoring rules."""

    def score(self, log, repeated_activity):
        score = 0
        reasons = []
        if log["suspicious_ip"]:
            score += 3
            reasons.append("suspicious IP (+3)")
        if log["unknown_domain"]:
            score += 2
            reasons.append("unknown domain (+2)")
        if repeated_activity:
            score += 4
            reasons.append("repeated activity (+4)")

        if score >= 7:
            severity = "High"
        elif score >= 3:
            severity = "Medium"
        else:
            severity = "Low"
        return score, severity, reasons


class AnomalyDetector:
    def __init__(self):
        self.failed_logins = defaultdict(deque)
        self.ip_users = defaultdict(set)
        self.user_login_hours = defaultdict(list)

    def build_login_baseline(self, logs):
        for log in logs:
            if log["status"] == "success":
                hour = datetime.fromisoformat(log["timestamp"].replace("Z", "+00:00")).hour
                self.user_login_hours[log["user"]].append(hour)

    def detect(self, log):
        time = datetime.fromisoformat(log["timestamp"].replace("Z", "+00:00"))
        flags = []
        self.ip_users[log["ip_address"]].add(log["user"])
        if len(self.ip_users[log["ip_address"]]) >= 3:
            flags.append("abnormal IP behavior: one IP used for multiple accounts")

        if log["status"] == "failure":
            key = (log["user"], log["ip_address"])
            failures = self.failed_logins[key]
            while failures and time - failures[0] > timedelta(minutes=10):
                failures.popleft()
            failures.append(time)
            if len(failures) >= 3:
                flags.append("repeated failed access: 3 failures in 10 minutes")

        if log["status"] == "success":
            hours = self.user_login_hours[log["user"]]
            if len(hours) >= 3 and hours.count(time.hour) == 1:
                flags.append("unusual login attempt: uncommon login hour")
        return flags


class SOCDashboardBackend:
    """JSON-backed dashboard logic: store logs, filter, and list top threats."""

    def __init__(self):
        self.logs = []

    def store_log(self, log):
        self.logs.append(log)

    def filter_by_severity(self, severity):
        return [log for log in self.logs if log["severity"] == severity]

    def get_top_threats(self):
        return sorted(self.logs, key=lambda log: log["risk_score"], reverse=True)[:10]


def read_json(file_name):
    with open(file_name, "r", encoding="utf-8") as file:
        return json.load(file)


def write_json(file_name, data):
    with open(file_name, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def main():
    # API security is represented without saving a real key in project files.
    demo_key = os.getenv(API_KEY_ENVIRONMENT_NAME, "week2-demo-key")
    api = SecureAPIService(demo_key)
    allowed, message = api.allow_request("local-file-import", demo_key, datetime.now())
    if not allowed:
        raise PermissionError(message)

    raw_logs = read_json(INPUT_FILE)
    threat_data = ThreatFeedClient().get_threat_data()
    enricher = LogEnricher(threat_data)
    scorer = RiskScorer()
    detector = AnomalyDetector()
    dashboard = SOCDashboardBackend()
    detector.build_login_baseline(raw_logs)

    activity_count = Counter((log["ip_address"], log["domain"]) for log in raw_logs)
    anomaly_alerts = []

    for raw_log in raw_logs:
        log = enricher.enrich(raw_log)
        repeated = activity_count[(log["ip_address"], log["domain"])] >= 3
        score, severity, reasons = scorer.score(log, repeated)
        log["risk_score"] = score
        log["severity"] = severity
        log["risk_reasons"] = reasons
        log["anomaly_flags"] = detector.detect(log)
        dashboard.store_log(log)
        if log["anomaly_flags"]:
            anomaly_alerts.append(log)

    report = {
        "project": "AI Security Data Processing Engine",
        "api_ingestion_status": message,
        "summary": {
            "total_logs": len(dashboard.logs),
            "high_severity_logs": len(dashboard.filter_by_severity("High")),
            "medium_severity_logs": len(dashboard.filter_by_severity("Medium")),
            "anomalies_detected": len(anomaly_alerts),
        },
        "enriched_logs": dashboard.logs,
        "top_10_threats": dashboard.get_top_threats(),
        "anomaly_alerts": anomaly_alerts,
    }
    write_json(REPORT_FILE, report)
    print("Processed", len(raw_logs), "logs. Report saved to", REPORT_FILE)
    print("High-severity logs:", report["summary"]["high_severity_logs"])


if __name__ == "__main__":
    main()
