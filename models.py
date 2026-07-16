"""SQLite data layer for RAVN AI."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Generator

from werkzeug.security import check_password_hash, generate_password_hash

from config import DATABASE


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                name TEXT NOT NULL,
                role TEXT DEFAULT 'Admin',
                organization TEXT DEFAULT 'RAVN Security'
            );
            CREATE TABLE IF NOT EXISTS websites (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                ssl_valid INTEGER DEFAULT 1,
                ssl_expiry TEXT,
                last_scan TEXT,
                threat_score INTEGER DEFAULT 0,
                health_score INTEGER DEFAULT 100,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                website_id TEXT,
                website_name TEXT,
                severity TEXT,
                title TEXT,
                description TEXT,
                status TEXT DEFAULT 'new',
                channel TEXT DEFAULT 'email',
                created_at TEXT NOT NULL,
                resolved_at TEXT
            );
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                website_id TEXT,
                website_name TEXT,
                report_type TEXT,
                summary TEXT,
                risk_score INTEGER,
                vulnerability_count INTEGER,
                threat_count INTEGER,
                generated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                website_id TEXT NOT NULL,
                scan_date TEXT NOT NULL,
                duration INTEGER,
                risk_score INTEGER,
                status TEXT,
                vulnerabilities_json TEXT,
                threat_count INTEGER DEFAULT 0
            );
        """)
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            _seed(conn)


def _seed(conn: sqlite3.Connection) -> None:
    conn.execute(
        "INSERT INTO users (email, password_hash, name, role, organization) VALUES (?, ?, ?, ?, ?)",
        ("admin@ravn.ai", generate_password_hash("admin123"), "Security Admin", "Admin", "RAVN Security"),
    )

    now = datetime.now(timezone.utc)
    websites = [
        ("ws-001", "Nexus Corp", "https://nexuscorp.com", "compromised", 1, "2027-03-15T00:00:00Z", (now - timedelta(minutes=10)).isoformat(), 94, 23, "2025-06-01T10:00:00Z"),
        ("ws-002", "CloudPay Solutions", "https://cloudpay.io", "active", 1, "2027-08-20T00:00:00Z", (now - timedelta(hours=1)).isoformat(), 12, 96, "2025-07-15T08:00:00Z"),
        ("ws-003", "EduPortal Global", "https://eduportal.org", "active", 0, "2025-12-01T00:00:00Z", (now - timedelta(hours=2)).isoformat(), 45, 68, "2025-04-10T14:00:00Z"),
        ("ws-004", "GovSecure Platform", "https://govsecure.gov", "scanning", 1, "2027-11-30T00:00:00Z", (now - timedelta(minutes=30)).isoformat(), 28, 82, "2025-09-05T09:00:00Z"),
        ("ws-005", "HealthNet Systems", "https://healthnet.care", "active", 1, "2027-06-15T00:00:00Z", (now - timedelta(hours=1, minutes=30)).isoformat(), 8, 98, "2025-05-20T11:00:00Z"),
        ("ws-006", "Demo Company", "https://demo-company.com", "active", 1, "2027-09-01T00:00:00Z", (now - timedelta(minutes=15)).isoformat(), 35, 74, "2025-11-01T16:00:00Z"),
    ]
    conn.executemany(
        "INSERT INTO websites VALUES (?,?,?,?,?,?,?,?,?,?)",
        websites,
    )

    alerts = [
        ("alert-001", "ws-001", "Nexus Corp", "critical", "Website Defacement Detected",
         "Visual analysis detected unauthorized modifications to the website header and footer.", "new", "slack", (now - timedelta(minutes=5)).isoformat(), None),
        ("alert-002", "ws-001", "Nexus Corp", "critical", "SQL Injection Vulnerability Found",
         "Critical SQL injection vulnerability detected in the login form.", "new", "email", (now - timedelta(minutes=10)).isoformat(), None),
        ("alert-003", "ws-003", "EduPortal Global", "high", "SSL Certificate Expired",
         "The SSL certificate for eduportal.org has expired.", "acknowledged", "email", (now - timedelta(hours=2)).isoformat(), None),
        ("alert-004", "ws-004", "GovSecure Platform", "medium", "Unusual Traffic Pattern",
         "AI detected a 340% increase in requests from known Tor exit nodes.", "new", "popup", (now - timedelta(minutes=30)).isoformat(), None),
        ("alert-005", "ws-006", "Demo Company", "low", "Missing Security Headers",
         "Application is not setting recommended security headers.", "resolved", "email", (now - timedelta(days=1)).isoformat(), (now - timedelta(hours=12)).isoformat()),
        ("alert-006", "ws-001", "Nexus Corp", "critical", "Malicious JavaScript Injection",
         "Obfuscated JavaScript detected attempting to exfiltrate credentials.", "new", "slack", (now - timedelta(minutes=3)).isoformat(), None),
    ]
    conn.executemany(
        "INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?)",
        alerts,
    )

    reports = [
        ("rpt-001", "ws-001", "Nexus Corp", "full", "Critical security incident detected. Website defacement with credential theft attempt.", 94, 6, 5, (now - timedelta(minutes=10)).isoformat()),
        ("rpt-002", "ws-002", "CloudPay Solutions", "executive", "All systems operational. Minor configuration improvements recommended.", 12, 1, 0, (now - timedelta(days=1)).isoformat()),
        ("rpt-003", "ws-003", "EduPortal Global", "compliance", "SSL certificate expired. Several compliance issues identified.", 45, 3, 2, (now - timedelta(days=2)).isoformat()),
    ]
    conn.executemany(
        "INSERT INTO reports VALUES (?,?,?,?,?,?,?,?,?)",
        reports,
    )


def verify_user(email: str, password: str) -> dict[str, Any] | None:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            return dict(row)
    return None


def create_user(email: str, password: str, name: str) -> bool:
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)",
                (email, generate_password_hash(password), name),
            )
        return True
    except sqlite3.IntegrityError:
        return False


def get_user_by_email(email: str) -> dict[str, Any] | None:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        return dict(row) if row else None


def get_dashboard_stats() -> dict[str, Any]:
    with get_db() as conn:
        websites = conn.execute("SELECT COUNT(*) FROM websites").fetchone()[0]
        threats = conn.execute("SELECT COUNT(*) FROM alerts WHERE status = 'new'").fetchone()[0]
        critical = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'critical' AND status != 'resolved'").fetchone()[0]
        last_scan = conn.execute("SELECT MAX(last_scan) FROM websites").fetchone()[0]
        avg_health = conn.execute("SELECT AVG(health_score) FROM websites").fetchone()[0] or 87
    return {
        "protected_websites": websites,
        "live_threats": threats,
        "critical_vulnerabilities": critical,
        "ai_health_score": int(avg_health),
        "last_scan": last_scan,
        "compliance_score": 92,
    }


def get_websites(search: str = "") -> list[dict[str, Any]]:
    with get_db() as conn:
        if search:
            rows = conn.execute(
                "SELECT * FROM websites WHERE name LIKE ? OR url LIKE ? ORDER BY name",
                (f"%{search}%", f"%{search}%"),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM websites ORDER BY name").fetchall()
        return [dict(r) for r in rows]


def get_website(website_id: str) -> dict[str, Any] | None:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM websites WHERE id = ?", (website_id,)).fetchone()
        return dict(row) if row else None


def add_website(name: str, url: str) -> str:
    wid = f"ws-{int(datetime.now().timestamp() * 1000)}"
    with get_db() as conn:
        conn.execute(
            "INSERT INTO websites (id, name, url, status, ssl_valid, threat_score, health_score, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (wid, name, url, "active", 1, 0, 100, utcnow()),
        )
    return wid


def remove_website(website_id: str) -> None:
    with get_db() as conn:
        conn.execute("DELETE FROM websites WHERE id = ?", (website_id,))
        conn.execute("DELETE FROM scans WHERE website_id = ?", (website_id,))


def update_website_after_scan(website_id: str, scan_result: dict[str, Any]) -> None:
    health = scan_result["health_score"]
    threat = 100 - health
    status = "compromised" if health < 70 else "active"
    ssl = scan_result["ssl"]
    with get_db() as conn:
        conn.execute(
            """UPDATE websites SET last_scan=?, ssl_valid=?, ssl_expiry=?,
               health_score=?, threat_score=?, status=? WHERE id=?""",
            (utcnow(), int(ssl["valid"]), ssl.get("expiry_date"), health, threat, status, website_id),
        )
        scan_id = f"scan-{int(datetime.now().timestamp() * 1000)}"
        conn.execute(
            """INSERT INTO scans (id, website_id, scan_date, duration, risk_score, status, vulnerabilities_json, threat_count)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                scan_id, website_id, utcnow(),
                max(1, scan_result["latency_ms"] // 1000),
                threat, "completed",
                json.dumps(scan_result["vulnerabilities"]),
                len(scan_result["vulnerabilities"]),
            ),
        )


def get_scans(website_id: str) -> list[dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM scans WHERE website_id = ? ORDER BY scan_date DESC",
            (website_id,),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["vulnerabilities"] = json.loads(item.pop("vulnerabilities_json") or "[]")
            result.append(item)
        return result


def get_alerts(severity: str = "all") -> list[dict[str, Any]]:
    with get_db() as conn:
        if severity == "all":
            rows = conn.execute("SELECT * FROM alerts ORDER BY created_at DESC").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE severity = ? ORDER BY created_at DESC",
                (severity,),
            ).fetchall()
        return [dict(r) for r in rows]


def update_alert_status(alert_id: str, status: str) -> None:
    resolved = utcnow() if status == "resolved" else None
    with get_db() as conn:
        conn.execute(
            "UPDATE alerts SET status = ?, resolved_at = COALESCE(?, resolved_at) WHERE id = ?",
            (status, resolved, alert_id),
        )


def get_reports() -> list[dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM reports ORDER BY generated_at DESC").fetchall()
        return [dict(r) for r in rows]


def get_threat_trend() -> list[dict[str, Any]]:
    import random
    data = []
    for i in range(30):
        date = datetime.now(timezone.utc) - timedelta(days=29 - i)
        base = random.randint(1, 5)
        spike = random.randint(3, 8) if i > 24 else 0
        threats = base + spike
        data.append({
            "date": date.strftime("%Y-%m-%d"),
            "threats": threats,
            "resolved": max(0, threats - random.randint(0, 2)),
        })
    return data


def get_risk_distribution() -> list[dict[str, Any]]:
    return [
        {"name": "Critical", "value": 7, "color": "#dc2626"},
        {"name": "High", "value": 12, "color": "#ea580c"},
        {"name": "Medium", "value": 18, "color": "#ca8a04"},
        {"name": "Low", "value": 8, "color": "#16a34a"},
        {"name": "Info", "value": 5, "color": "#2563eb"},
    ]
