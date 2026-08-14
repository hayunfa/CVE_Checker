"""저장소 계층.

`Store` 추상 클래스 + `SqliteStore` 구현.
나중에 Supabase(Postgres) 로 옮길 때는 `Store` 를 구현한 클래스 하나만 새로 쓰고
main.py 의 생성 부분 한 줄만 바꾸면 된다 (다른 모듈은 Store 인터페이스만 본다).
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .logutil import get_logger
from .normalize import Finding

log = get_logger("store")

SCHEMA = """
CREATE TABLE IF NOT EXISTS run_log (
  run_id TEXT PRIMARY KEY,          -- yyyyMMddHHmmss
  started_at TEXT, finished_at TEXT,
  lookback_days INTEGER,
  scope_desc TEXT,                  -- SCOPE 한 줄 요약
  scope_json TEXT,                  -- 확정된 Scope 객체 전문(JSON)
  truncated_cnt INTEGER,            -- max_rows 로 잘려나간 건수
  source_stat TEXT,                 -- JSON {"NVD":123,"OSV":45,...} / 실패 소스 포함
  total_cnt INTEGER, new_cnt INTEGER, updated_cnt INTEGER,
  excel_file TEXT,
  status TEXT,                      -- SUCCESS / PARTIAL / FAILED / SKIPPED
  error_msg TEXT
);

CREATE TABLE IF NOT EXISTS cve (
  cve_id TEXT, sw_name TEXT, vendor TEXT,
  affected_range TEXT, fixed_version TEXT,
  severity TEXT, cvss_score REAL, cvss_vector TEXT,
  published_date TEXT, modified_date TEXT,   -- YYYYMMDD
  kev_yn TEXT, summary TEXT, reference_url TEXT,
  source TEXT, ecosystem TEXT,
  first_seen_run TEXT, last_seen_run TEXT, collected_at TEXT,
  content_hash TEXT,                          -- 변경 감지용
  PRIMARY KEY (cve_id, sw_name)
);

CREATE TABLE IF NOT EXISTS mail_log (
  mail_seq INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT, recipient TEXT, subject TEXT,
  sent_at TEXT, status TEXT,        -- SENT / FAILED / SKIPPED
  error_msg TEXT, attach_file TEXT
);
CREATE INDEX IF NOT EXISTS ix_cve_run ON cve(last_seen_run);
CREATE INDEX IF NOT EXISTS ix_cve_sw ON cve(sw_name);
CREATE INDEX IF NOT EXISTS ix_mail_run ON mail_log(run_id);
"""

CVE_COLUMNS = (
    "cve_id", "sw_name", "vendor", "affected_range", "fixed_version",
    "severity", "cvss_score", "cvss_vector", "published_date", "modified_date",
    "kev_yn", "summary", "reference_url", "source", "ecosystem",
    "first_seen_run", "last_seen_run", "collected_at", "content_hash",
)


def content_hash(finding: Finding) -> str:
    """변경 감지용 해시. 이 5개 값 중 하나라도 바뀌면 'updated' 로 본다."""
    score = "" if finding.cvss_score is None else f"{float(finding.cvss_score):.1f}"
    raw = "|".join([
        finding.affected_range or "",
        finding.fixed_version or "",
        finding.severity or "",
        score,
        finding.summary or "",
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ==========================================================================
#  추상 인터페이스  (Supabase 교체 지점)
# ==========================================================================
class Store(ABC):
    @abstractmethod
    def init_schema(self) -> None: ...

    @abstractmethod
    def start_run(self, run_id: str, scope) -> None: ...

    @abstractmethod
    def finish_run(self, run_id: str, **fields: Any) -> None: ...

    @abstractmethod
    def upsert_findings(self, findings: Sequence[Finding],
                        run_id: str) -> Dict[str, List[Finding]]: ...

    @abstractmethod
    def fetch_run_cves(self, run_id: str) -> List[Dict[str, Any]]: ...

    @abstractmethod
    def fetch_all_cves(self, limit: Optional[int] = None) -> List[Dict[str, Any]]: ...

    @abstractmethod
    def fetch_runs(self, limit: int = 30) -> List[Dict[str, Any]]: ...

    @abstractmethod
    def log_mail(self, run_id: str, recipient: str, subject: str,
                 status: str, error_msg: str = "", attach_file: str = "") -> None: ...

    @abstractmethod
    def fetch_mail_logs(self, run_id: Optional[str] = None) -> List[Dict[str, Any]]: ...

    @abstractmethod
    def close(self) -> None: ...


# ==========================================================================
#  SQLite 구현
# ==========================================================================
class SqliteStore(Store):
    def __init__(self, db_path: str | Path = "data/cve.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=DELETE")   # 커밋 대상이라 WAL 미사용
        self.init_schema()

    # ---------------- 스키마 ----------------
    def init_schema(self) -> None:
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # ---------------- 실행 로그 ----------------
    def start_run(self, run_id: str, scope) -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO run_log
               (run_id, started_at, lookback_days, scope_desc, scope_json,
                truncated_cnt, source_stat, total_cnt, new_cnt, updated_cnt,
                excel_file, status, error_msg)
               VALUES (?,?,?,?,?,0,'{}',0,0,0,'','RUNNING','')""",
            (run_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
             scope.lookback_days, scope.desc, scope.to_json()),
        )
        self.conn.commit()

    def finish_run(self, run_id: str, **fields: Any) -> None:
        allowed = {"finished_at", "truncated_cnt", "source_stat", "total_cnt",
                   "new_cnt", "updated_cnt", "excel_file", "status", "error_msg",
                   "scope_desc", "scope_json", "lookback_days"}
        payload = {k: v for k, v in fields.items() if k in allowed}
        payload.setdefault("finished_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        if isinstance(payload.get("source_stat"), (dict, list)):
            payload["source_stat"] = json.dumps(payload["source_stat"], ensure_ascii=False)
        assignments = ", ".join(f"{k}=?" for k in payload)
        self.conn.execute(
            f"UPDATE run_log SET {assignments} WHERE run_id=?",
            (*payload.values(), run_id),
        )
        self.conn.commit()

    # ---------------- CVE ----------------
    def upsert_findings(self, findings: Sequence[Finding],
                        run_id: str) -> Dict[str, List[Finding]]:
        """신규/변경/무변경으로 나눠 저장한다.

        content_hash 가 기존 행과 다르면 'updated', 행 자체가 없으면 'new'.
        """
        result: Dict[str, List[Finding]] = {"new": [], "updated": [], "unchanged": []}
        cursor = self.conn.cursor()

        for finding in findings:
            digest = content_hash(finding)
            row = cursor.execute(
                "SELECT content_hash, first_seen_run FROM cve WHERE cve_id=? AND sw_name=?",
                (finding.cve_id, finding.sw_name),
            ).fetchone()

            if row is None:
                state = "new"
                first_seen = run_id
            elif row["content_hash"] != digest:
                state = "updated"
                first_seen = row["first_seen_run"] or run_id
            else:
                state = "unchanged"
                first_seen = row["first_seen_run"] or run_id

            values = (
                finding.cve_id, finding.sw_name, finding.vendor,
                finding.affected_range, finding.fixed_version,
                finding.severity, finding.cvss_score, finding.cvss_vector,
                finding.published_date, finding.modified_date,
                finding.kev_yn, finding.summary, finding.reference_url,
                finding.source, finding.ecosystem,
                first_seen, run_id, finding.collected_at, digest,
            )
            placeholders = ",".join("?" * len(CVE_COLUMNS))
            cursor.execute(
                f"INSERT OR REPLACE INTO cve ({','.join(CVE_COLUMNS)}) "
                f"VALUES ({placeholders})", values)
            result[state].append(finding)

        self.conn.commit()
        log.info("DB 반영: 신규 %d건 / 변경 %d건 / 동일 %d건",
                 len(result["new"]), len(result["updated"]), len(result["unchanged"]))
        return result

    def fetch_run_cves(self, run_id: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM cve WHERE last_seen_run=? ORDER BY cve_id", (run_id,)).fetchall()
        return [dict(r) for r in rows]

    def fetch_all_cves(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = ("SELECT * FROM cve ORDER BY "
               "CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 "
               "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, "
               "cvss_score DESC, sw_name, cve_id")
        if limit:
            sql += f" LIMIT {int(limit)}"
        return [dict(r) for r in self.conn.execute(sql).fetchall()]

    def fetch_runs(self, limit: int = 30) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM run_log ORDER BY run_id DESC LIMIT ?", (int(limit),)).fetchall()
        return [dict(r) for r in rows]

    def fetch_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute(
            "SELECT * FROM run_log WHERE run_id=?", (run_id,)).fetchone()
        return dict(row) if row else None

    # ---------------- 메일 ----------------
    def log_mail(self, run_id: str, recipient: str, subject: str,
                 status: str, error_msg: str = "", attach_file: str = "") -> None:
        self.conn.execute(
            """INSERT INTO mail_log
               (run_id, recipient, subject, sent_at, status, error_msg, attach_file)
               VALUES (?,?,?,?,?,?,?)""",
            (run_id, recipient, subject,
             datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
             status, error_msg or "", attach_file or ""),
        )
        self.conn.commit()

    def fetch_mail_logs(self, run_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if run_id:
            rows = self.conn.execute(
                "SELECT * FROM mail_log WHERE run_id=? ORDER BY mail_seq", (run_id,)).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM mail_log ORDER BY mail_seq DESC LIMIT 500").fetchall()
        return [dict(r) for r in rows]

    # ---------------- 통계 (열람 페이지용) ----------------
    def severity_counts(self) -> Dict[str, int]:
        rows = self.conn.execute(
            "SELECT severity, COUNT(*) AS cnt FROM cve GROUP BY severity").fetchall()
        return {r["severity"] or "NONE": r["cnt"] for r in rows}

    def sw_counts(self, top: int = 20) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT sw_name, COUNT(*) AS cnt FROM cve "
            "GROUP BY sw_name ORDER BY cnt DESC, sw_name LIMIT ?", (int(top),)).fetchall()
        return [dict(r) for r in rows]

    def mail_stat_by_run(self) -> Dict[str, Dict[str, int]]:
        rows = self.conn.execute(
            "SELECT run_id, status, COUNT(*) AS cnt FROM mail_log "
            "GROUP BY run_id, status").fetchall()
        stat: Dict[str, Dict[str, int]] = {}
        for row in rows:
            stat.setdefault(row["run_id"], {})[row["status"]] = row["cnt"]
        return stat

    def total_cve_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0]

    def close(self) -> None:
        try:
            self.conn.commit()
            self.conn.close()
        except sqlite3.Error:
            pass


def rows_to_findings(rows: Iterable[Dict[str, Any]]) -> List[Finding]:
    """DB 행 → Finding (엑셀·메일 재사용용)."""
    findings: List[Finding] = []
    for row in rows:
        findings.append(Finding(
            cve_id=row.get("cve_id", ""),
            sw_name=row.get("sw_name", ""),
            source=row.get("source", ""),
            vendor=row.get("vendor", "") or "",
            ecosystem=row.get("ecosystem", "other") or "other",
            affected_range=row.get("affected_range", "*") or "*",
            fixed_version=row.get("fixed_version", "") or "",
            severity=row.get("severity", "NONE") or "NONE",
            cvss_score=row.get("cvss_score"),
            cvss_vector=row.get("cvss_vector", "") or "",
            published_date=row.get("published_date", "") or "",
            modified_date=row.get("modified_date", "") or "",
            kev_yn=row.get("kev_yn", "N") or "N",
            summary=row.get("summary", "") or "",
            reference_url=row.get("reference_url", "") or "",
            collected_at=row.get("collected_at", "") or "",
        ))
    return findings
