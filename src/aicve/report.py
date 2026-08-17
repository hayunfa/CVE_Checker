"""DB 조회 도구 — 수집·발송 결과를 터미널에서 바로 확인한다.

SQL 을 몰라도 쓸 수 있게 자주 보는 화면을 명령 하나로 묶어 놨다.

    python -m src.aicve.report                 최근 실행 + 메일 발송 요약
    python -m src.aicve.report --mails         메일 발송 로그 전체
    python -m src.aicve.report --run 20260816211121   특정 회차 상세(CVE 목록 포함)
    python -m src.aicve.report --cves          누적 CVE 목록
    python -m src.aicve.report --stats         심각도·S/W별 통계
    python -m src.aicve.report --sql "SELECT ..."     직접 조회(읽기 전용)

읽기만 하므로 DB 를 망가뜨릴 걱정은 없다.
"""
from __future__ import annotations

import argparse
import sys
from typing import Any, Dict, List, Sequence

from .store import SqliteStore

BAR = "=" * 112
DASH = "-" * 112


def _out(text: str = "") -> None:
    print(text)


def _table(rows: Sequence[Dict[str, Any]], columns: Sequence[tuple],
           empty: str = "기록이 없습니다.") -> None:
    """columns = [(표시이름, 키, 너비), ...]"""
    if not rows:
        _out(f"  {empty}")
        return
    header = "  ".join(f"{name:<{width}}" for name, _, width in columns)
    _out("  " + header)
    _out("  " + "-" * len(header))
    for row in rows:
        cells = []
        for _, key, width in columns:
            value = row.get(key)
            text = "" if value is None else str(value)
            text = text.replace("\n", " ").replace("\t", " ")
            if len(text) > width:
                text = text[: width - 1] + "…"
            cells.append(f"{text:<{width}}")
        _out("  " + "  ".join(cells))


# --------------------------------------------------------------------------
def show_summary(store: SqliteStore, limit: int) -> None:
    runs = store.fetch_runs(limit)
    mail_stat = store.mail_stat_by_run()

    _out(BAR)
    _out(f" 실행 이력 (최근 {len(runs)}회)")
    _out(BAR)
    if not runs:
        _out("  아직 실행 기록이 없습니다.")
        return

    for run in runs:
        stat = mail_stat.get(run["run_id"], {})
        mail = (f"메일 성공 {stat.get('SENT', 0)}"
                f" / 실패 {stat.get('FAILED', 0)}"
                f" / 생략 {stat.get('SKIPPED', 0)}")
        _out(f"\n  {run['run_id']}  [{run['status']}]  {run['started_at']}"
             f" ~ {run['finished_at'] or '진행 중'}")
        _out(f"    {run['scope_desc']}")
        _out(f"    수집 {run['total_cnt'] or 0}건"
             f" / 신규 {run['new_cnt'] or 0}"
             f" / 변경 {run['updated_cnt'] or 0}"
             f" / 잘림 {run['truncated_cnt'] or 0}"
             f"    엑셀 {run['excel_file'] or '-'}")
        _out(f"    소스별 {run['source_stat'] or '-'}")
        _out(f"    {mail}")
        if run["error_msg"]:
            _out(f"    ⚠ 사유: {run['error_msg']}")

    _out()
    _out(DASH)
    _out(f"  누적 CVE {store.total_cve_count()}건"
         f" · 심각도별 {store.severity_counts()}")


def show_mails(store: SqliteStore, run_id: str | None) -> None:
    logs = store.fetch_mail_logs(run_id)
    _out(BAR)
    _out(f" 메일 발송 로그{f' — 실행 {run_id}' if run_id else ' (최근 500건)'}")
    _out(BAR)
    _table(logs, [
        ("순번", "mail_seq", 5),
        ("실행번호", "run_id", 15),
        ("발송시각", "sent_at", 20),
        ("상태", "status", 8),
        ("수신자", "recipient", 26),
        ("첨부", "attach_file", 20),
    ], empty="발송 기록이 없습니다.")

    failed = [r for r in logs if r["status"] == "FAILED"]
    skipped = [r for r in logs if r["status"] == "SKIPPED"]
    _out()
    _out(f"  합계 {len(logs)}건 — 성공 {sum(1 for r in logs if r['status'] == 'SENT')}"
         f" / 실패 {len(failed)} / 생략 {len(skipped)}")
    for row in failed + skipped:
        if row["error_msg"]:
            _out(f"    · {row['recipient']} [{row['status']}] {row['error_msg']}")
    if logs:
        # 전체 조회는 최신순, 회차별 조회는 순번순이라 정렬 방향이 다르다.
        # 어느 쪽이든 가장 큰 순번이 최신이다.
        latest = max(logs, key=lambda r: r["mail_seq"])
        _out(f"\n  최근 제목: {latest['subject']}")


def show_run(store: SqliteStore, run_id: str) -> int:
    run = store.fetch_run(run_id)
    if not run:
        _out(f"실행번호 {run_id} 를 찾을 수 없습니다.")
        _out("  → python -m src.aicve.report   로 실행번호 목록을 먼저 확인하세요.")
        return 1

    _out(BAR)
    _out(f" 실행 {run_id} 상세  [{run['status']}]")
    _out(BAR)
    _out(f"  기간   {run['started_at']} ~ {run['finished_at'] or '진행 중'}")
    _out(f"  조건   {run['scope_desc']}")
    _out(f"  결과   수집 {run['total_cnt'] or 0} / 신규 {run['new_cnt'] or 0}"
         f" / 변경 {run['updated_cnt'] or 0} / 잘림 {run['truncated_cnt'] or 0}")
    _out(f"  소스별 {run['source_stat'] or '-'}")
    _out(f"  엑셀   {run['excel_file'] or '-'}")
    if run["error_msg"]:
        _out(f"  ⚠ 사유 {run['error_msg']}")

    cves = store.fetch_run_cves(run_id)
    _out()
    _out(f" 이 회차 CVE ({len(cves)}건)")
    _out(DASH)
    _table(cves, [
        ("CVE", "cve_id", 17),
        ("S/W", "sw_name", 20),
        ("심각도", "severity", 9),
        ("점수", "cvss_score", 5),
        ("영향 버전", "affected_range", 26),
        ("조치버전", "fixed_version", 12),
        ("KEV", "kev_yn", 4),
    ], empty="이 회차에 기록된 CVE 가 없습니다.")

    _out()
    show_mails(store, run_id)
    return 0


def show_cves(store: SqliteStore, limit: int) -> None:
    cves = store.fetch_all_cves(limit)
    _out(BAR)
    _out(f" 누적 CVE (상위 {len(cves)}건 / 전체 {store.total_cve_count()}건)")
    _out(BAR)
    _table(cves, [
        ("CVE", "cve_id", 17),
        ("S/W", "sw_name", 20),
        ("심각도", "severity", 9),
        ("점수", "cvss_score", 5),
        ("영향 버전", "affected_range", 24),
        ("조치버전", "fixed_version", 12),
        ("KEV", "kev_yn", 4),
        ("최근회차", "last_seen_run", 15),
    ], empty="수집된 CVE 가 없습니다.")


def show_stats(store: SqliteStore, top: int) -> None:
    _out(BAR)
    _out(" 통계")
    _out(BAR)
    counts = store.severity_counts()
    total = sum(counts.values()) or 1
    _out(f"\n  심각도별 (누적 {sum(counts.values())}건)")
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"):
        count = counts.get(level, 0)
        bar = "█" * round(count / total * 50)
        _out(f"    {level:9} {count:5}  {bar}")

    rows = store.sw_counts(top)
    peak = max((r["cnt"] for r in rows), default=1)
    _out(f"\n  S/W별 Top {len(rows)}")
    for row in rows:
        bar = "█" * round(row["cnt"] / peak * 50)
        _out(f"    {row['sw_name'][:24]:24} {row['cnt']:5}  {bar}")


def run_sql(store: SqliteStore, sql: str) -> int:
    """직접 조회. 안전을 위해 SELECT 만 허용한다."""
    head = sql.strip().lstrip("(").split(None, 1)[0].upper() if sql.strip() else ""
    if head not in ("SELECT", "WITH"):
        _out("조회(SELECT/WITH) 만 실행할 수 있습니다. 데이터를 바꾸는 명령은 막혀 있습니다.")
        return 1
    try:
        cursor = store.conn.execute(sql)
    except Exception as exc:
        _out(f"SQL 오류: {exc}")
        return 1
    rows = cursor.fetchall()
    if not rows:
        _out("결과가 없습니다.")
        return 0
    names = [d[0] for d in cursor.description]
    _out("  " + " | ".join(names))
    _out("  " + "-" * 100)
    for row in rows[:500]:
        _out("  " + " | ".join("" if v is None else str(v) for v in row))
    if len(rows) > 500:
        _out(f"  … 외 {len(rows) - 500}건")
    return 0


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.aicve.report",
        description="수집·발송 결과를 DB에서 조회합니다 (읽기 전용).",
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--db", default="data/cve.db", help="DB 파일 경로")
    parser.add_argument("--mails", action="store_true", help="메일 발송 로그 전체")
    parser.add_argument("--run", metavar="실행번호", help="특정 회차 상세")
    parser.add_argument("--cves", action="store_true", help="누적 CVE 목록")
    parser.add_argument("--stats", action="store_true", help="심각도·S/W별 통계")
    parser.add_argument("--sql", metavar="구문", help="직접 조회 (SELECT 만)")
    parser.add_argument("--limit", type=int, default=30, help="표시 건수 (기본 30)")
    args = parser.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

    store = SqliteStore(args.db)
    try:
        if args.sql:
            return run_sql(store, args.sql)
        if args.run:
            return show_run(store, args.run)
        if args.mails:
            show_mails(store, None)
        elif args.cves:
            show_cves(store, args.limit)
        elif args.stats:
            show_stats(store, args.limit)
        else:
            show_summary(store, args.limit)
        return 0
    finally:
        store.close()


if __name__ == "__main__":
    sys.exit(main())
