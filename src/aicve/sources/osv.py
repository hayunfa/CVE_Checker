"""OSV.dev 수집.

버전 범위가 가장 정확한 소스라 병합 시 AFFECTED_RANGE / FIXED_VERSION 은 OSV 를 우선 채택한다.

  1) POST /v1/querybatch  — 패키지 좌표를 묶어서 취약점 ID 목록을 받는다
  2) modified 날짜로 조회 구간 밖의 건을 먼저 걸러낸다 (상세 조회 횟수 절약)
  3) GET /v1/vulns/{id}   — 상세를 받아 affected[].ranges[].events 로 버전범위 산출

단독 실행:  python -m src.aicve.sources.osv --groups serving --lookback 30
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple

from ..logutil import get_logger
from ..normalize import (
    Finding,
    cvss31_base_score,
    join_ranges,
    osv_affected_to_exprs,
    osv_fixed_version,
    severity_from_score,
    severity_from_text,
    to_yyyymmdd,
)
from .base import SourceError, SourceResult, build_client, now_stamp

log = get_logger("osv")

QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"

# watchlist 의 좌표 키 → OSV ecosystem 이름
ECOSYSTEM_MAP = {"pypi": "PyPI", "npm": "npm", "go": "Go"}


def build_queries(scope) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """(OSV 질의, 대응하는 watchlist 항목) 목록을 만든다."""
    queries: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    for target in scope.targets:
        for key, ecosystem in ECOSYSTEM_MAP.items():
            name = target.get(key)
            if not name:
                continue
            queries.append((
                {"package": {"name": str(name), "ecosystem": ecosystem}},
                target,
            ))
    return queries


def _cve_id_of(vuln: Dict[str, Any]) -> Optional[str]:
    """OSV 레코드에서 CVE ID 를 뽑는다. CVE 가 없는 권고는 제외한다."""
    vuln_id = str(vuln.get("id", "")).upper()
    if vuln_id.startswith("CVE-"):
        return vuln_id
    for alias in vuln.get("aliases") or []:
        text = str(alias).upper()
        if text.startswith("CVE-"):
            return text
    return None


def _severity_of(vuln: Dict[str, Any]) -> Tuple[Optional[float], str, str]:
    """(점수, 벡터, 등급). OSV 는 점수 없이 벡터만 주는 경우가 많아 직접 계산한다."""
    vector = ""
    for item in vuln.get("severity") or []:
        if str(item.get("type", "")).upper().startswith("CVSS_V3"):
            vector = str(item.get("score", ""))
            break
    if not vector:
        for item in vuln.get("severity") or []:
            vector = str(item.get("score", ""))
            if vector:
                break

    score = cvss31_base_score(vector)
    if score is not None:
        return score, vector, severity_from_score(score)

    text = (vuln.get("database_specific") or {}).get("severity")
    return None, vector, severity_from_text(text)


def _reference_of(vuln: Dict[str, Any]) -> str:
    references = vuln.get("references") or []
    for wanted in ("ADVISORY", "WEB", "REPORT"):
        for ref in references:
            if str(ref.get("type", "")).upper() == wanted and ref.get("url"):
                return str(ref["url"])
    if references and references[0].get("url"):
        return str(references[0]["url"])
    return f"https://osv.dev/vulnerability/{vuln.get('id', '')}"


def _affected_for(vuln: Dict[str, Any], package_name: str,
                  ecosystem: str, range_max_len: int) -> Tuple[str, str]:
    """해당 패키지에 대한 (범위식, 조치버전)."""
    exprs: List[str] = []
    fixed = ""
    wanted = package_name.lower().replace("_", "-")
    for affected in vuln.get("affected") or []:
        package = affected.get("package") or {}
        name = str(package.get("name", "")).lower().replace("_", "-")
        eco = str(package.get("ecosystem", "")).split(":")[0]
        if name != wanted or eco.lower() != ecosystem.lower():
            continue
        exprs.extend(osv_affected_to_exprs(affected))
        fixed = fixed or osv_fixed_version(affected)
    return join_ranges(exprs, range_max_len), fixed


def collect(scope) -> SourceResult:
    """조회 구간 안에서 수정된 OSV 취약점을 수집한다."""
    result = SourceResult(name="OSV")
    started = time.time()
    client = build_client(scope)
    range_max_len = int(scope.output.get("range_max_len", 500))
    summary_max_len = int(scope.output.get("summary_max_len", 1000))
    batch_size = int(scope.collect.get("osv_batch_size", 100))
    start_date, end_date = scope.date_range()
    start_key, end_key = start_date.strftime("%Y%m%d"), end_date.strftime("%Y%m%d")
    stamp = now_stamp()

    try:
        pairs = build_queries(scope)
        if not pairs:
            log.warning("OSV 조회 가능한 패키지 좌표(pypi/npm/go)가 없습니다.")
            return result

        # ---------- 1) querybatch ----------
        wanted: Dict[str, List[Tuple[Dict[str, Any], Dict[str, Any]]]] = {}
        for offset in range(0, len(pairs), batch_size):
            chunk = pairs[offset:offset + batch_size]
            payload = {"queries": [q for q, _ in chunk]}
            data = client.post_json(QUERYBATCH_URL, payload)
            for (query, target), entry in zip(chunk, data.get("results") or []):
                if entry.get("next_page_token"):
                    log.warning("%s 결과가 많아 일부만 조회됩니다(page token 존재).",
                                query["package"]["name"])
                for vuln in entry.get("vulns") or []:
                    modified = to_yyyymmdd(vuln.get("modified"))
                    if modified and not (start_key <= modified <= end_key):
                        continue          # 조회 구간 밖 → 상세 조회 생략
                    wanted.setdefault(str(vuln.get("id")), []).append((query, target))

        log.info("OSV 배치 조회 완료: 상세 조회 대상 %d건 (패키지 좌표 %d개)",
                 len(wanted), len(pairs))

        # ---------- 2) 상세 조회 ----------
        skipped_no_cve = 0
        for vuln_id, owners in wanted.items():
            try:
                vuln = client.get_json(VULN_URL.format(vuln_id=vuln_id))
            except SourceError as exc:
                log.warning("OSV 상세 조회 실패 %s: %s", vuln_id, exc)
                continue

            cve_id = _cve_id_of(vuln)
            if not cve_id:
                skipped_no_cve += 1
                continue

            if vuln.get("withdrawn"):
                continue

            score, vector, severity = _severity_of(vuln)
            summary = (vuln.get("details") or vuln.get("summary") or "")[:summary_max_len * 2]
            reference = _reference_of(vuln)
            published = to_yyyymmdd(vuln.get("published"))
            modified = to_yyyymmdd(vuln.get("modified"))

            seen_targets: set = set()
            for query, target in owners:
                canonical = target["canonical_name"]
                if canonical in seen_targets:
                    continue
                seen_targets.add(canonical)
                package = query["package"]
                affected_range, fixed = _affected_for(
                    vuln, package["name"], package["ecosystem"], range_max_len)
                result.findings.append(Finding(
                    cve_id=cve_id,
                    sw_name=canonical,
                    source="OSV",
                    vendor=target.get("vendor", "") or "",
                    ecosystem=target.get("ecosystem", "other"),
                    affected_range=affected_range,
                    fixed_version=fixed,
                    severity=severity,
                    cvss_score=score,
                    cvss_vector=vector,
                    published_date=published,
                    modified_date=modified,
                    summary=summary,
                    reference_url=reference,
                    collected_at=stamp,
                ))

        if skipped_no_cve:
            log.info("CVE 번호가 없는 OSV 권고 %d건은 제외했습니다.", skipped_no_cve)
        log.info("OSV 수집 완료: %d건", len(result.findings))

    except SourceError as exc:
        result.ok = False
        result.error = str(exc)
        log.error("OSV 수집 실패 — 이 소스만 건너뜁니다: %s", exc)
    except Exception as exc:
        result.ok = False
        result.error = f"{type(exc).__name__}: {exc}"
        log.exception("OSV 수집 중 예상치 못한 오류")
    finally:
        result.requests_made = client.request_count
        result.elapsed_sec = time.time() - started
        client.close()
    return result


if __name__ == "__main__":
    from .base import print_findings, standalone_scope

    scope_obj, limit = standalone_scope("OSV.dev 단독 수집")
    print(scope_obj.desc)
    print_findings(collect(scope_obj), limit)
