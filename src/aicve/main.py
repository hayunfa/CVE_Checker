"""오케스트레이션 진입점.

    수집(NVD/OSV/GHSA/KEV) → 병합·정규화 → DB 적재(신규/변경 판정)
      → 엑셀(CVE_YYYYMMDD.xls) → 메일 발송 → 열람 페이지(docs/) 생성

원칙: 어떤 단계가 실패해도 나머지는 진행한다.
  - 소스 일부 실패 → status=PARTIAL, 나머지 소스로 계속
  - 메일 실패      → 엑셀·DB·페이지는 정상 생성
  - 종료 코드      → 0(SUCCESS/PARTIAL/SKIPPED), 1(FAILED)

사용 예)
    python -m src.aicve.main --preset daily
    python -m src.aicve.main --preset urgent --groups serving,ui
    python -m src.aicve.main --from 2026-01-01 --to 2026-01-31 --excel-scope all
    python -m src.aicve.main --show-scope          # 조건만 확인하고 종료
"""
from __future__ import annotations

import argparse
import json
import sys
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .excel import ExcelResult, cleanup_old_files, select_rows, write_excel
from .logutil import get_logger, new_run_id, setup_logging
from .normalize import (
    Finding,
    build_watch_index,
    filter_by_severity,
    merge_findings,
    sort_findings,
)
from .scope import Scope, ScopeError, resolve_scope
from .store import SqliteStore, rows_to_findings

log = get_logger("main")

EXIT_OK = 0
EXIT_FAILED = 1


# ==========================================================================
#  CLI
# ==========================================================================
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m src.aicve.main",
        description="AI 오픈소스 CVE 수집 → 엑셀 → 메일 → DB → 열람 페이지",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    # --- 3.5절 9개 축 ---
    parser.add_argument("--preset", default=None,
                        choices=["daily", "urgent", "in_use", "monthly", "backfill"],
                        help="사전 정의 조합 (settings.yml: presets)")
    parser.add_argument("--lookback", dest="lookback_days", default=None,
                        help="조회 기간(일). 기본 3")
    parser.add_argument("--backfill", dest="backfill", default=None,
                        help="첫 실행용. --lookback 과 동일하게 동작 (예: --backfill 30)")
    parser.add_argument("--from", dest="date_from", default=None,
                        help="시작일 YYYY-MM-DD (지정 시 --lookback 무시)")
    parser.add_argument("--to", dest="date_to", default=None, help="종료일 YYYY-MM-DD")
    parser.add_argument("--min-severity", dest="min_severity", default=None,
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "ALL"],
                        help="심각도 하한. KEV 등재 건은 이 값과 무관하게 항상 포함")
    parser.add_argument("--groups", default=None,
                        help="대상 그룹(쉼표). 예: framework,serving")
    parser.add_argument("--sw-names", dest="sw_names", default=None,
                        help="특정 S/W만(쉼표). 지정 시 --groups·--only-in-use 무시")
    parser.add_argument("--only-in-use", dest="only_in_use", action="store_true",
                        default=None, help="watchlist 의 in_use=true 만")
    parser.add_argument("--sources", default=None,
                        help="사용할 소스(쉼표). 예: osv,kev")
    parser.add_argument("--excel-scope", dest="excel_scope", default=None,
                        choices=["delta", "all"],
                        help="delta=신규·변경만(기본) / all=이번 실행 전량")
    parser.add_argument("--max-rows", dest="max_rows", default=None,
                        help="엑셀 최대 행수. 초과분은 심각도·점수 순으로 잘라낸다")
    # --- 실행 제어 ---
    parser.add_argument("--skip-mail", dest="skip_mail", action="store_true",
                        help="메일 발송 생략")
    parser.add_argument("--dry-run", dest="dry_run", action="store_true",
                        help="메일을 보내지 않고 본문 미리보기만 저장")
    parser.add_argument("--show-scope", dest="show_scope", action="store_true",
                        help="API 호출 없이 확정된 Scope 한 줄만 출력하고 종료")
    parser.add_argument("--skip-site", dest="skip_site", action="store_true",
                        help="docs/ 페이지 생성 생략")
    # --- 경로 ---
    parser.add_argument("--config", default="config/settings.yml")
    parser.add_argument("--watchlist", default="config/watchlist.yml")
    parser.add_argument("--db", default="data/cve.db")
    parser.add_argument("--out-dir", dest="out_dir", default="output")
    parser.add_argument("--docs-dir", dest="docs_dir", default="docs")
    parser.add_argument("--templates", default="templates")
    parser.add_argument("--mail-list", dest="mail_list", default="mail_list.txt")
    return parser


def cli_overrides(args: argparse.Namespace) -> Dict[str, Any]:
    """argparse 결과 → Scope 병합용 딕셔너리. 빈 값은 넣지 않는다."""
    values = {
        "preset": args.preset,
        "lookback_days": args.backfill or args.lookback_days,
        "date_from": args.date_from,
        "date_to": args.date_to,
        "min_severity": args.min_severity,
        "groups": args.groups,
        "sw_names": args.sw_names,
        "only_in_use": args.only_in_use,
        "sources": args.sources,
        "excel_scope": args.excel_scope,
        "max_rows": args.max_rows,
        "skip_mail": args.skip_mail,
        "dry_run": args.dry_run,
    }
    return {k: v for k, v in values.items()
            if v is not None and not (isinstance(v, str) and not v.strip())}


# ==========================================================================
#  수집
# ==========================================================================
def collect_all(scope: Scope) -> tuple[List[Finding], set, Dict[str, Any], List[str]]:
    """소스별 수집. 실패한 소스는 건너뛰고 계속 진행한다.

    돌려주는 값: (전체 findings, KEV ID 집합, 소스별 통계, 실패한 소스 이름들)
    """
    from .sources import ghsa, kev, nvd, osv

    findings: List[Finding] = []
    kev_ids: set = set()
    stats: Dict[str, Any] = {}
    failed: List[str] = []

    # KEV 를 먼저 받아 두면 심각도 필터에서 예외 처리를 바로 할 수 있다
    if scope.has_source("kev"):
        result = kev.collect(scope)
        kev_ids = result.kev_ids
        stats["KEV"] = len(kev_ids) if result.ok else f"FAILED: {result.error[:80]}"
        if not result.ok:
            failed.append("KEV")

    for name, module in (("osv", osv), ("nvd", nvd), ("ghsa", ghsa)):
        if not scope.has_source(name):
            continue
        result = module.collect(scope)
        stats[result.name] = (result.count if result.ok
                              else f"FAILED: {result.error[:80]}")
        if result.ok:
            findings.extend(result.findings)
        else:
            failed.append(result.name)
        log.info(result.summary())

    return findings, kev_ids, stats, failed


# ==========================================================================
#  실행
# ==========================================================================
def run(args: argparse.Namespace) -> int:
    run_id = new_run_id()
    setup_logging(run_id)

    # ---------- 1. 수집 범위 확정 ----------
    try:
        scope = resolve_scope(cli=cli_overrides(args),
                              settings_path=args.config,
                              watchlist_path=args.watchlist)
    except ScopeError as exc:
        log.error("수집 범위 설정 오류: %s", exc)
        return EXIT_FAILED

    log.info(scope.desc)                     # ★ 실행 로그 첫 줄
    if args.show_scope:
        print(scope.desc)
        print(f"대상 S/W {len(scope.targets)}종: "
              f"{', '.join(scope.target_names) if scope.targets else '(없음)'}")
        return EXIT_OK

    store = SqliteStore(args.db)
    status, error_msg = "SUCCESS", ""
    excel: Optional[ExcelResult] = None
    truncated = 0
    new_cnt = updated_cnt = 0
    stats: Dict[str, Any] = {}

    try:
        # ---------- 2. 대상 0건이면 즉시 종료 ----------
        if not scope.targets:
            reason = ("수집 대상 S/W 가 0건입니다. "
                      f"(groups={','.join(scope.groups)}, "
                      f"sw_names={','.join(scope.sw_names) or '-'}, "
                      f"only_in_use={scope.only_in_use})")
            if scope.unmatched_sw:
                reason += f" / watchlist 에 없는 이름: {', '.join(scope.unmatched_sw)}"
            log.warning(reason)
            store.start_run(run_id, scope)
            store.finish_run(run_id, status="SKIPPED", error_msg=reason,
                             source_stat={}, total_cnt=0, new_cnt=0, updated_cnt=0)
            return EXIT_OK

        store.start_run(run_id, scope)
        log.info("수집 대상 %d종 / 소스 %s", len(scope.targets), ",".join(scope.sources))

        # ---------- 3. 수집 ----------
        raw, kev_ids, stats, failed_sources = collect_all(scope)
        if failed_sources:
            status = "PARTIAL"
            error_msg = f"일부 소스 실패: {', '.join(failed_sources)}"
        if not raw and failed_sources:
            status = "FAILED"
            error_msg = f"모든 소스 수집 실패: {', '.join(failed_sources)}"

        # ---------- 4. 병합 · 정규화 · 필터 ----------
        merged = merge_findings(
            raw, kev_ids=kev_ids,
            watch_index=build_watch_index(scope.targets),
            range_max_len=int(scope.output.get("range_max_len", 500)),
            summary_max_len=int(scope.output.get("summary_max_len", 1000)),
        )
        # 소스가 버전 정보를 안 준 건은 요약문에서 2차 추출한다.
        # ('*' 는 내부망 도구가 '모든 버전 영향' 으로 읽어 오탐을 만든다)
        # 반드시 번역 전에 — 패턴이 영문 표현 기준이다.
        try:
            from .summary_range import recover_missing_ranges

            recovered = recover_missing_ranges(
                merged,
                range_max_len=int(scope.output.get("range_max_len", 500)),
                summary_max_len=int(scope.output.get("summary_max_len", 1000)))
            if recovered:
                stats["RANGE_RECOVERED"] = recovered
        except Exception:
            log.exception("요약문 범위 추출 실패 — '*' 로 두고 계속합니다.")

        filtered = filter_by_severity(merged, scope)
        log.info("병합 %d건 → 심각도 필터(%s, KEV 예외) 통과 %d건",
                 len(merged), scope.min_severity, len(filtered))

        # ---------- 4-1. SUMMARY 번역 (settings.yml: output.translate) ----------
        # 실패해도 영문 원문이 남으므로 실행을 멈추지 않는다.
        try:
            from .translate import translate_findings

            stat = translate_findings(filtered, scope, store)
            if stat.failed:
                stats["TRANSLATE"] = (f"{stat.translated}건 번역 / "
                                      f"{stat.failed}건 실패")
            elif stat.translated or stat.cached:
                stats["TRANSLATE"] = f"{stat.translated}건 번역 / {stat.cached}건 캐시"
        except Exception as exc:
            log.exception("번역 처리 실패 — 영문 원문으로 계속합니다.")
            stats["TRANSLATE"] = f"FAILED: {exc}"

        # ---------- 5. DB 적재 (신규/변경 판정) ----------
        changes = store.upsert_findings(filtered, run_id)
        new_cnt, updated_cnt = len(changes["new"]), len(changes["updated"])

        # ---------- 6. 엑셀 대상 선정 ----------
        if scope.excel_scope == "delta":
            candidates = changes["new"] + changes["updated"]
        else:
            candidates = list(filtered)
        rows, truncated = select_rows(candidates, scope.max_rows)
        if truncated:
            log.warning("최대 행수(%d) 초과로 %d건을 엑셀에서 제외했습니다.",
                        scope.max_rows, truncated)

        # ---------- 7. 엑셀 ----------
        # 담을 행이 없으면 파일을 만들지 않는다.
        # 같은 날 두 번째 실행(신규 0건)이 오전에 만든 엑셀을 빈 파일로 덮어쓰는 것을 막는다.
        try:
            if rows:
                excel = write_excel(rows, scope, run_id, out_dir=args.out_dir,
                                    new_cnt=new_cnt, updated_cnt=updated_cnt,
                                    truncated_cnt=truncated)
            else:
                log.info("엑셀에 담을 행이 0건이라 파일을 만들지 않았습니다 "
                         "(기존 %s 파일을 덮어쓰지 않습니다).", scope.excel_scope)
            cleanup_old_files(args.out_dir,
                              int(scope.output.get("retention_days", 90)))
        except Exception as exc:
            status = "PARTIAL" if status == "SUCCESS" else status
            error_msg = (error_msg + " / " if error_msg else "") + f"엑셀 생성 실패: {exc}"
            log.exception("엑셀 생성 실패 — 나머지 단계는 계속합니다.")

        # ---------- 8. 메일 ----------
        try:
            from .mailer import send_mail

            mail_result = send_mail(
                scope, store, run_id, rows, excel,
                new_cnt=new_cnt, updated_cnt=updated_cnt, truncated_cnt=truncated,
                source_stat=stats, recipients_path=args.mail_list,
                template_dir=args.templates, preview_dir=args.out_dir,
                all_findings=candidates)
            if mail_result.failed:
                status = "PARTIAL" if status == "SUCCESS" else status
                error_msg = ((error_msg + " / " if error_msg else "")
                             + f"메일 발송 실패 {len(mail_result.failed)}건")
        except Exception as exc:
            status = "PARTIAL" if status == "SUCCESS" else status
            error_msg = (error_msg + " / " if error_msg else "") + f"메일 처리 실패: {exc}"
            log.exception("메일 처리 실패 — 나머지 단계는 계속합니다.")

        # ---------- 9. run_log 마무리 (페이지 생성 전에 반영) ----------
        store.finish_run(
            run_id, status=status, error_msg=error_msg,
            source_stat=stats, total_cnt=len(filtered),
            new_cnt=new_cnt, updated_cnt=updated_cnt, truncated_cnt=truncated,
            excel_file=excel.file_name if excel else "")

        # ---------- 10. 열람 페이지 ----------
        if not args.skip_site:
            try:
                from .site import build_site

                build_site(scope, store, run_id, excel,
                           docs_dir=args.docs_dir, template_dir=args.templates)
            except Exception as exc:
                status = "PARTIAL" if status == "SUCCESS" else status
                error_msg = (error_msg + " / " if error_msg else "") + f"페이지 생성 실패: {exc}"
                log.exception("페이지 생성 실패 — 실행은 계속 마무리합니다.")
                store.finish_run(run_id, status=status, error_msg=error_msg)

        log.info("실행 완료 [%s] 수집 %d건 / 신규 %d / 변경 %d / 잘림 %d",
                 status, len(filtered), new_cnt, updated_cnt, truncated)
        return EXIT_OK if status != "FAILED" else EXIT_FAILED

    except KeyboardInterrupt:
        log.warning("사용자가 중단했습니다.")
        store.finish_run(run_id, status="FAILED", error_msg="사용자 중단",
                         source_stat=stats)
        return EXIT_FAILED
    except Exception as exc:
        log.exception("예상치 못한 오류로 실행이 중단됐습니다.")
        store.finish_run(run_id, status="FAILED",
                         error_msg=f"{type(exc).__name__}: {exc}"[:500],
                         source_stat=stats, new_cnt=new_cnt, updated_cnt=updated_cnt,
                         truncated_cnt=truncated,
                         excel_file=excel.file_name if excel else "")
        # 실패해도 지금까지의 결과로 페이지는 갱신해 둔다
        if not args.skip_site:
            try:
                from .site import build_site

                build_site(scope, store, run_id, excel,
                           docs_dir=args.docs_dir, template_dir=args.templates)
            except Exception:
                log.warning("실패 후 페이지 갱신도 실패했습니다.")
        return EXIT_FAILED
    finally:
        store.close()


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
