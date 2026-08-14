"""열람 페이지 생성 (Jinja2 → docs/, GitHub Pages).

  docs/index.html          대시보드 (실행 이력·심각도 누적·S/W Top N·최근 신규 CVE)
  docs/runs/{run_id}.html  실행 상세 (해당 회차 CVE 전체 + 메일 발송 로그)
  docs/cve/index.html      전체 CVE 검색 (순수 JS 클라이언트 필터)
  docs/data/*.json         데이터 재활용용
  docs/output/CVE_*.xls    엑셀 사본 (페이지에서 바로 내려받기)

외부 CSS/JS(CDN)를 쓰지 않아 사내망·오프라인에서도 그대로 열린다.
"""
from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .excel import ExcelResult
from .logutil import get_logger

log = get_logger("site")

MAX_SEARCH_ROWS = 5000          # 검색 페이지에 인라인으로 심는 최대 건수


def _env(template_dir: str | Path) -> Environment:
    return Environment(
        loader=FileSystemLoader(str(template_dir), encoding="utf-8"),
        autoescape=select_autoescape(["html", "xml", "j2"]),
        trim_blocks=True, lstrip_blocks=True,
    )


def _source_stat_text(raw: Any) -> str:
    """run_log.source_stat(JSON) → 'NVD=12 OSV=34' 형태."""
    if not raw:
        return "-"
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
    except (TypeError, ValueError):
        return str(raw)
    if not isinstance(data, dict):
        return str(raw)
    return " ".join(f"{k}={v}" for k, v in data.items()) or "-"


def _decorate_runs(runs: List[Dict[str, Any]],
                   mail_stat: Dict[str, Dict[str, int]]) -> List[Dict[str, Any]]:
    for run in runs:
        stat = mail_stat.get(run["run_id"], {})
        run["mail_sent"] = stat.get("SENT", 0)
        run["mail_failed"] = stat.get("FAILED", 0)
        run["mail_skipped"] = stat.get("SKIPPED", 0)
        run["source_stat_text"] = _source_stat_text(run.get("source_stat"))
    return runs


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def copy_outputs(excel: Optional[ExcelResult], docs_dir: Path) -> None:
    """엑셀 산출물을 docs/output/ 으로 복사해 페이지에서 바로 내려받게 한다."""
    if not excel:
        return
    target = docs_dir / "output"
    target.mkdir(parents=True, exist_ok=True)
    for path in excel.paths():
        if path.exists():
            shutil.copy2(path, target / path.name)


def build_site(scope, store, run_id: Optional[str] = None,
               excel: Optional[ExcelResult] = None,
               docs_dir: str | Path = "docs",
               template_dir: str | Path = "templates") -> List[Path]:
    """docs/ 전체를 다시 생성한다. 생성된 파일 경로 목록을 돌려준다."""
    docs_dir = Path(docs_dir)
    env = _env(template_dir)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    written: List[Path] = []

    recent = int(scope.site.get("recent_runs", 30))
    top_sw = int(scope.site.get("top_sw", 20))

    runs = _decorate_runs(store.fetch_runs(recent), store.mail_stat_by_run())
    latest = runs[0] if runs else None
    latest_run_id = run_id or (latest["run_id"] if latest else None)
    latest_cves = store.fetch_run_cves(latest_run_id) if latest_run_id else []

    all_cves = store.fetch_all_cves()
    severity_counts = store.severity_counts()
    sw_counts = store.sw_counts(top_sw)

    # ---------- 대시보드 ----------
    written.append(_write(docs_dir / "index.html", env.get_template("index.html.j2").render(
        page="index", root="", generated_at=generated_at,
        runs=runs, latest=latest, latest_cves=latest_cves,
        severity_counts=severity_counts,
        severity_max=max(severity_counts.values()) if severity_counts else 0,
        sw_counts=sw_counts,
        sw_max=max((s["cnt"] for s in sw_counts), default=0),
        total_cve=store.total_cve_count(),
    )))

    # ---------- 실행 상세 ----------
    run_template = env.get_template("run.html.j2")
    for run in runs:
        mail_logs = store.fetch_mail_logs(run["run_id"])
        written.append(_write(
            docs_dir / "runs" / f"{run['run_id']}.html",
            run_template.render(
                page="run", root="../", generated_at=generated_at,
                run=run, cves=store.fetch_run_cves(run["run_id"]),
                mail_logs=mail_logs,
                mail_sent=run["mail_sent"], mail_failed=run["mail_failed"],
            )))

    # ---------- 전체 CVE 검색 ----------
    search_rows = all_cves[:MAX_SEARCH_ROWS]
    written.append(_write(docs_dir / "cve" / "index.html", env.get_template("cve.html.j2").render(
        page="cve", root="../", generated_at=generated_at,
        cves=search_rows,
        sw_names=sorted({c["sw_name"] for c in search_rows}),
        cve_json=json.dumps(search_rows, ensure_ascii=False),
    )))
    if len(all_cves) > MAX_SEARCH_ROWS:
        log.warning("검색 페이지에는 상위 %d건만 실었습니다 (전체 %d건). "
                    "나머지는 all.json 을 이용하세요.", MAX_SEARCH_ROWS, len(all_cves))

    # ---------- 데이터 ----------
    written.append(_write(docs_dir / "data" / "latest.json", json.dumps(
        {"run_id": latest_run_id,
         "generated_at": generated_at,
         "scope_desc": latest["scope_desc"] if latest else "",
         "count": len(latest_cves),
         "cves": latest_cves},
        ensure_ascii=False, indent=1)))
    written.append(_write(docs_dir / "data" / "all.json", json.dumps(
        {"generated_at": generated_at, "count": len(all_cves), "cves": all_cves},
        ensure_ascii=False, indent=1)))

    # GitHub Pages 가 _ 로 시작하는 경로를 무시하지 않도록
    written.append(_write(docs_dir / ".nojekyll", ""))

    copy_outputs(excel, docs_dir)
    log.info("열람 페이지 생성 완료: %s (%d개 파일, 실행 %d회, CVE %d건)",
             docs_dir, len(written), len(runs), len(all_cves))
    return written


if __name__ == "__main__":
    # 단독 실행: 수집 없이 현재 DB 로 docs/ 만 다시 만든다
    from .logutil import new_run_id, setup_logging
    from .scope import resolve_scope
    from .store import SqliteStore

    setup_logging(new_run_id())
    scope_obj = resolve_scope(cli={})
    store_obj = SqliteStore("data/cve.db")
    try:
        build_site(scope_obj, store_obj)
    finally:
        store_obj.close()
