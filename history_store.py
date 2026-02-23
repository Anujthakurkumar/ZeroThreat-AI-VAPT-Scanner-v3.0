"""
ZeroThreat - Scan History Store (SQLite) + Diff Engine
Persists all scan results and detects changes between scans.
"""

import sqlite3
import json
import os
import time
from datetime import datetime
from dataclasses import asdict
from pathlib import Path

DB_PATH = Path(__file__).parent / "zerothreat_history.db"


# ─────────────────────────────────────────
#  DATABASE SETUP
# ─────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     TEXT UNIQUE NOT NULL,
            target      TEXT NOT NULL,
            scan_type   TEXT,
            profile     TEXT,
            risk_score  REAL,
            risk_label  TEXT,
            host_status TEXT,
            total_findings INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count     INTEGER DEFAULT 0,
            medium_count   INTEGER DEFAULT 0,
            low_count      INTEGER DEFAULT 0,
            open_ports_count INTEGER DEFAULT 0,
            started_at  TEXT,
            finished_at TEXT,
            created_at  TEXT DEFAULT (datetime('now')),
            result_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_target ON scans (target);
        CREATE INDEX IF NOT EXISTS idx_started ON scans (started_at);

        CREATE TABLE IF NOT EXISTS findings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     TEXT NOT NULL,
            target      TEXT NOT NULL,
            finding_id  TEXT,
            title       TEXT,
            severity    TEXT,
            cvss_score  REAL,
            adjusted_score REAL,
            confidence  TEXT,
            affected    TEXT,
            evidence    TEXT,
            category    TEXT,  -- 'network' | 'web'
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
        );

        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings (scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_target ON findings (target);
    """)
    conn.commit()
    conn.close()

init_db()


# ─────────────────────────────────────────
#  STORE
# ─────────────────────────────────────────

def save_scan(result) -> int:
    """Save a ScanResult (dataclass or dict) to SQLite. Returns row id."""
    if hasattr(result, '__dataclass_fields__'):
        d = asdict(result)
    else:
        d = result

    summary  = d.get("summary", {})
    by_sev   = summary.get("by_severity", {})
    conn     = get_db()

    try:
        cur = conn.execute("""
            INSERT OR REPLACE INTO scans
              (scan_id, target, scan_type, profile, risk_score, risk_label,
               host_status, total_findings, critical_count, high_count, medium_count,
               low_count, open_ports_count, started_at, finished_at, result_json)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            d.get("scan_id",""),
            d.get("target",""),
            d.get("scan_type",""),
            d.get("profile","normal"),
            d.get("risk_score", 0),
            d.get("risk_label",""),
            d.get("host_status",""),
            summary.get("total", 0),
            by_sev.get("CRITICAL", 0),
            by_sev.get("HIGH", 0),
            by_sev.get("MEDIUM", 0),
            by_sev.get("LOW", 0),
            len(d.get("open_ports", [])),
            d.get("started_at",""),
            d.get("finished_at",""),
            json.dumps(d),
        ))
        row_id = cur.lastrowid

        # Store individual findings for efficient querying
        conn.execute("DELETE FROM findings WHERE scan_id=?", (d.get("scan_id",""),))
        rows = []
        for v in d.get("vulnerabilities", []):
            rows.append((d["scan_id"], d["target"], v.get("id"), v.get("title"),
                         v.get("severity"), v.get("cvss_score",0), v.get("adjusted_score",0),
                         v.get("confidence",""), v.get("affected",""), v.get("evidence",""), "network"))
        for v in d.get("web_findings", []):
            rows.append((d["scan_id"], d["target"], v.get("id"), v.get("title"),
                         v.get("severity"), v.get("cvss_score",0), v.get("adjusted_score",0),
                         v.get("confidence",""), v.get("affected",""), v.get("evidence",""), "web"))
        conn.executemany("""
            INSERT INTO findings
              (scan_id,target,finding_id,title,severity,cvss_score,adjusted_score,
               confidence,affected,evidence,category)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, rows)

        conn.commit()
        return row_id
    finally:
        conn.close()


def list_scans(target=None, limit=50) -> list:
    conn = get_db()
    try:
        if target:
            rows = conn.execute("""
                SELECT id, scan_id, target, scan_type, profile, risk_score, risk_label,
                       host_status, total_findings, critical_count, high_count,
                       open_ports_count, started_at, finished_at
                FROM scans WHERE target=? ORDER BY started_at DESC LIMIT ?
            """, (target, limit)).fetchall()
        else:
            rows = conn.execute("""
                SELECT id, scan_id, target, scan_type, profile, risk_score, risk_label,
                       host_status, total_findings, critical_count, high_count,
                       open_ports_count, started_at, finished_at
                FROM scans ORDER BY started_at DESC LIMIT ?
            """, (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_scan(scan_id) -> dict:
    conn = get_db()
    try:
        row = conn.execute("SELECT result_json FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
        if row:
            return json.loads(row["result_json"])
        return None
    finally:
        conn.close()


def delete_scan(scan_id):
    conn = get_db()
    try:
        conn.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
        conn.execute("DELETE FROM scans WHERE scan_id=?", (scan_id,))
        conn.commit()
    finally:
        conn.close()


def get_targets() -> list:
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT target, COUNT(*) as scan_count,
                   MAX(started_at) as last_scan,
                   AVG(risk_score) as avg_risk
            FROM scans GROUP BY target ORDER BY last_scan DESC
        """).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ─────────────────────────────────────────
#  DIFF ENGINE
# ─────────────────────────────────────────

def diff_scans(scan_id_old: str, scan_id_new: str) -> dict:
    """
    Compare two scans of the same target.
    Returns a diff report: new issues, fixed issues, changed ports, risk delta.
    """
    old = get_scan(scan_id_old)
    new = get_scan(scan_id_new)

    if not old or not new:
        return {"error": "One or both scan IDs not found"}

    def vuln_key(v): return v.get("id","") + "|" + v.get("affected","")

    old_vulns = {vuln_key(v): v for v in old.get("vulnerabilities",[]) + old.get("web_findings",[])}
    new_vulns = {vuln_key(v): v for v in new.get("vulnerabilities",[]) + new.get("web_findings",[])}

    new_findings   = [v for k, v in new_vulns.items() if k not in old_vulns]
    fixed_findings = [v for k, v in old_vulns.items() if k not in new_vulns]
    persisting     = [v for k, v in new_vulns.items() if k in old_vulns]

    # Port changes
    old_ports = {p["port"] for p in old.get("open_ports",[])}
    new_ports = {p["port"] for p in new.get("open_ports",[])}
    ports_opened = sorted(new_ports - old_ports)
    ports_closed = sorted(old_ports - new_ports)

    # Risk delta
    old_risk = old.get("risk_score", 0)
    new_risk = new.get("risk_score", 0)
    risk_delta = round(new_risk - old_risk, 1)

    # Severity regression detection
    severity_order = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"INFO":0}
    regressions = []
    for k, old_v in old_vulns.items():
        if k in new_vulns:
            old_sev = severity_order.get(old_v.get("severity","INFO"),0)
            new_sev = severity_order.get(new_vulns[k].get("severity","INFO"),0)
            if new_sev > old_sev:
                regressions.append({
                    "title": old_v.get("title"),
                    "old_severity": old_v.get("severity"),
                    "new_severity": new_vulns[k].get("severity"),
                })

    # Summary text
    summary_lines = []
    if new_findings:
        summary_lines.append(f"🔴 {len(new_findings)} NEW finding(s) detected")
    if fixed_findings:
        summary_lines.append(f"✅ {len(fixed_findings)} finding(s) remediated")
    if ports_opened:
        summary_lines.append(f"⚠️  {len(ports_opened)} new port(s) opened: {ports_opened}")
    if ports_closed:
        summary_lines.append(f"ℹ️  {len(ports_closed)} port(s) closed: {ports_closed}")
    if risk_delta > 0:
        summary_lines.append(f"📈 Risk score increased by {risk_delta} ({old_risk} → {new_risk})")
    elif risk_delta < 0:
        summary_lines.append(f"📉 Risk score decreased by {abs(risk_delta)} ({old_risk} → {new_risk})")
    if regressions:
        summary_lines.append(f"⚠️  {len(regressions)} finding(s) escalated in severity")
    if not summary_lines:
        summary_lines.append("✅ No changes detected between scans")

    return {
        "old_scan_id":     scan_id_old,
        "new_scan_id":     scan_id_new,
        "target":          new.get("target"),
        "old_scan_time":   old.get("started_at"),
        "new_scan_time":   new.get("started_at"),
        "risk_delta":      risk_delta,
        "old_risk_score":  old_risk,
        "new_risk_score":  new_risk,
        "old_risk_label":  old.get("risk_label"),
        "new_risk_label":  new.get("risk_label"),
        "new_findings":    new_findings,
        "fixed_findings":  fixed_findings,
        "persisting":      persisting,
        "regressions":     regressions,
        "ports_opened":    ports_opened,
        "ports_closed":    ports_closed,
        "summary":         "\n".join(summary_lines),
    }


def get_risk_trend(target: str, limit=10) -> list:
    """Returns risk score over time for a target (for trending charts)."""
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT started_at, risk_score, risk_label, total_findings,
                   critical_count, high_count
            FROM scans WHERE target=?
            ORDER BY started_at ASC LIMIT ?
        """, (target, limit)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
