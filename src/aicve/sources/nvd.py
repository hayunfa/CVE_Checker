"""NVD CVE API 2.0 수집.

감시 대상별 `keywordSearch` + `lastModStartDate`/`lastModEndDate` 로 조회한다.
CVSS 점수와 영문 요약은 NVD 가 가장 정확해 병합 시 우선 채택된다.

레이트 리밋
  - API 키 없음 : 30초당 5요청  → 요청 간 6.5초 대기
  - API 키 있음 : 30초당 50요청 → 요청 간 0.7초 대기  (NVD_API_KEY 환경변수)
  - 조회 구간은 한 번에 최대 120일이므로 그보다 길면 나눠서 요청한다.

단독 실행:  python -m src.aicve.sources.nvd --sw-names PyTorch --lookback 30
"""
from __future__ import annotations

import os
import re
import time
from datetime import date, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..logutil import get_logger
from ..normalize import (
    Finding,
    cvss31_base_score,
    join_ranges,
    nvd_cpe_match_to_expr,
    severity_from_score,
    severity_from_text,
    to_yyyymmdd,
)
from .base import SourceError, SourceResult, build_client, now_stamp

log = get_logger("nvd")

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_WINDOW_DAYS = 120           # NVD 가 허용하는 최대 조회 구간
CPE_PRODUCT_FIELD = 4


def _windows(start: date, end: date) -> List[Tuple[date, date]]:
    """120일을 넘는 구간을 나눈다."""
    chunks: List[Tuple[date, date]] = []
    cursor = start
    while cursor <= end:
        stop = min(cursor + timedelta(days=MAX_WINDOW_DAYS - 1), end)
        chunks.append((cursor, stop))
        cursor = stop + timedelta(days=1)
    return chunks


def _iso(day: date, end_of_day: bool = False) -> str:
    return f"{day.isoformat()}T{'23:59:59.999' if end_of_day else '00:00:00.000'}"


def _description(cve: Dict[str, Any]) -> str:
    descriptions = cve.get("descriptions") or []
    for item in descriptions:
        if item.get("lang") == "en":
            return str(item.get("value", ""))
    return str(descriptions[0].get("value", "")) if descriptions else ""


def _metrics(cve: Dict[str, Any]) -> Tuple[Optional[float], str, str]:
    """(점수, 벡터, 등급). v3.1 → v3.0 → v2 순으로 본다."""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        for entry in metrics.get(key) or []:
            data = entry.get("cvssData") or {}
            vector = str(data.get("vectorString", ""))
            score = data.get("baseScore")
            if score is None:
                score = cvss31_base_score(vector)
            if score is not None:
                return float(score), vector, severity_from_score(score)
            severity = data.get("baseSeverity") or entry.get("baseSeverity")
            if severity:
                return None, vector, severity_from_text(severity)
    for entry in metrics.get("cvssMetricV2") or []:
        data = entry.get("cvssData") or {}
        return (float(data["baseScore"]) if data.get("baseScore") is not None else None,
                str(data.get("vectorString", "")),
                severity_from_text(entry.get("baseSeverity")))
    return None, "", "NONE"


def _reference(cve: Dict[str, Any]) -> str:
    references = cve.get("references") or []
    for ref in references:
        tags = [str(t).upper() for t in (ref.get("tags") or [])]
        if "VENDOR ADVISORY" in tags or "PATCH" in tags:
            return str(ref.get("url", ""))
    if references:
        return str(references[0].get("url", ""))
    return f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}"


def _cpe_matches(cve: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                yield match


def _product_tokens(target: Dict[str, Any]) -> set:
    """CPE product 필드와 비교할 토큰들."""
    tokens = {str(target["canonical_name"]).lower()}
    tokens |= {str(a).lower() for a in (target.get("aliases") or [])}
    if target.get("cpe_keyword"):
        tokens.add(str(target["cpe_keyword"]).lower())
    if target.get("pypi"):
        tokens.add(str(target["pypi"]).lower())
    expanded = set()
    for token in tokens:
        expanded.add(token)
        expanded.add(token.replace(" ", "_"))
        expanded.add(token.replace(" ", ""))
        expanded.add(token.replace("-", "_"))
    return {t for t in expanded if t}


def _matching_cpes(cve: Dict[str, Any], tokens: set) -> List[Dict[str, Any]]:
    """이 CVE 의 CPE 중 대상 제품에 해당하는 것들."""
    hits: List[Dict[str, Any]] = []
    for match in _cpe_matches(cve):
        criteria = str(match.get("criteria") or match.get("cpe23Uri") or "")
        fields = criteria.split(":")
        if len(fields) <= CPE_PRODUCT_FIELD:
            continue
        product = fields[CPE_PRODUCT_FIELD].lower()
        if product in tokens:
            hits.append(match)
    return hits


# 제품명이 '권고문의 주어' 임을 알려주는 표시
#   "vLLM is an inference engine" / "Apache Airflow's serializer" / "n8n before 1.2.3"
#   "... in Elasticsearch can lead to denial of service"
#     ↑ CWE 번호가 앞에 붙어 제품명이 뒤로 밀리는 권고문(Elastic 계열)이 많아
#       조동사(can/may/could)도 주어 표시로 인정한다. 이걸 빼면 진짜 건을 놓친다.
_SUBJECT_MARKER = re.compile(
    r"^\s*(?:'s\b|s'\b"
    r"|(?:is|are|was|were|has|have|allows?|contains?|fails?|does|do|did)\b"
    r"|(?:can|could|may|might|will|would)\b"
    r"|(?:before|prior\s+to|through|thru|up\s+to|versions?|version)\b"
    r"|v?\d+\.\d)", re.I)

# 주어부를 찾지 못했을 때 대신 볼 앞부분 길이
SUBJECT_WINDOW = 80

# 서술어가 시작되는 지점. 이 앞까지가 '주어부' 다.
#   "CyberPanel before 3.0.0 contains ..."          주어부 = "CyberPanel"
#   "Uncontrolled Recursion (CWE-674) in Elasticsearch can lead to ..."
#                                                    주어부 = "... in Elasticsearch"
_PREDICATE_START = re.compile(
    r"\b(?:is|are|was|were|has|have|allows?|contains?|fails?|does|do|did"
    r"|can|could|may|might|will|would"
    r"|before|prior\s+to|through|thru|versions?|version)\b", re.I)


def _subject_phrase(text: str) -> str:
    """서술어 앞까지(= 주어부)를 잘라낸다."""
    match = _PREDICATE_START.search(text)
    return text[:match.start()] if match else text[:SUBJECT_WINDOW]


def _mentions(text: str, name: str) -> List[int]:
    """제품명이 '낱말로' 등장하는 위치들.

    'elasticsearch_memory' 처럼 더 긴 식별자의 일부인 것은 언급으로 치지 않는다.
    """
    positions: List[int] = []
    start = 0
    while True:
        position = text.find(name, start)
        if position < 0:
            return positions
        end = position + len(name)
        start = end
        before = text[position - 1] if position else " "
        after = text[end] if end < len(text) else " "
        if before.isalnum() or before == "_" or after.isalnum() or after == "_":
            continue
        positions.append(position)


def _subject_names(target: Dict[str, Any]) -> List[str]:
    """주어 판정에 쓸 제품명들. 짧고 흔한 별칭은 오탐이 커서 제외한다."""
    names = [str(target["canonical_name"])]
    if target.get("cpe_keyword"):
        names.append(str(target["cpe_keyword"]))
    for alias in target.get("aliases") or []:
        text = str(alias)
        if len(text) >= 5 and "/" not in text:
            names.append(text)
    seen: List[str] = []
    for name in names:
        key = name.lower()
        if key and key not in seen:
            seen.append(key)
    return seen


def _is_subject(description: str, target: Dict[str, Any]) -> bool:
    """제품이 이 권고문의 '대상' 인지 판정한다.

    NVD keywordSearch 는 설명에 이름이 스치기만 해도 물어온다.
    예) CyberPanel 취약점인데 "WebTerminal FastAPI SSH service" 라는 이유로 FastAPI 에,
        etcd 취약점인데 "Watch gRPC API" 라는 이유로 gRPC 에 붙는다.
    실제 대상인 경우 제품명은 거의 항상 첫 문장 도입부에 주어로 등장한다.
    """
    text = (description or "").lower()
    if not text:
        return False
    phrase = _subject_phrase(text)

    for name in _subject_names(target):
        positions = _mentions(text, name)
        if not positions:
            continue
        # (a) 주어부 안에 이름이 있으면 이 권고문의 대상이다
        #     "CyberPanel before 3.0.0 ... FastAPI SSH service" 의 주어부는
        #     "CyberPanel" 뿐이라 FastAPI 는 여기서 걸러진다.
        if _mentions(phrase, name):
            return True
        # (b) 뒤에 주어 표시가 붙어 있으면 대상으로 본다
        #     "... of Elasticsearch can lead to ..." 처럼 주어부 판정이 빗나가는 문장 대비
        for position in positions:
            if _SUBJECT_MARKER.match(text[position + len(name):]):
                return True
    return False


def _is_relevant(cve: Dict[str, Any], target: Dict[str, Any],
                 tokens: set) -> Tuple[bool, str]:
    """keywordSearch 결과가 정말 이 제품 건인지 확인한다.

    돌려주는 값: (채택 여부, 사유)

      1. CPE 가 이 제품과 맞으면      → 채택 (NVD 가 분석해 붙인 식별자라 가장 확실)
      2. CPE 는 있는데 다른 제품이면  → 제외 (NVD 가 "이건 그 제품 건" 이라고 판단한 것)
      3. CPE 가 아직 없으면(신규 CVE) → 설명에서 '주어' 인지로 판정
    """
    if _matching_cpes(cve, tokens):
        return True, "cpe"
    if any(True for _ in _cpe_matches(cve)):
        return False, "cpe-mismatch"
    if _is_subject(_description(cve), target):
        return True, "subject"
    return False, "mention-only"


def _ranges_and_fixed(cve: Dict[str, Any], tokens: set,
                      range_max_len: int) -> Tuple[str, str]:
    exprs: List[str] = []
    fixed_candidates: List[str] = []
    for match in _matching_cpes(cve, tokens):
        if match.get("vulnerable") is False:
            continue
        exprs.append(nvd_cpe_match_to_expr(match))
        if match.get("versionEndExcluding"):
            fixed_candidates.append(str(match["versionEndExcluding"]))
    fixed = fixed_candidates[0] if len(set(fixed_candidates)) == 1 else ""
    return join_ranges(exprs, range_max_len), fixed


def _vendor(cve: Dict[str, Any], tokens: set, fallback: str) -> str:
    for match in _matching_cpes(cve, tokens):
        fields = str(match.get("criteria") or "").split(":")
        if len(fields) > 3 and fields[3] not in ("*", "-", ""):
            return fields[3].replace("_", " ")
    return fallback


def collect(scope) -> SourceResult:
    """감시 대상별로 NVD 를 조회한다."""
    result = SourceResult(name="NVD")
    started = time.time()

    api_key = os.environ.get("NVD_API_KEY", "").strip()
    headers = {"apiKey": api_key} if api_key else {}
    client = build_client(scope, headers)
    sleep_sec = float(scope.collect.get(
        "nvd_sleep_with_key" if api_key else "nvd_sleep_no_key", 0.7 if api_key else 6.5))
    per_page = int(scope.collect.get("nvd_results_per_page", 2000))
    range_max_len = int(scope.output.get("range_max_len", 500))
    summary_max_len = int(scope.output.get("summary_max_len", 1000))
    stamp = now_stamp()

    start_date, end_date = scope.date_range()
    windows = _windows(start_date, end_date)
    log.info("NVD 조회 시작: 대상 %d종 × 구간 %d개 (API 키 %s, 요청 간 %.1f초)",
             len(scope.targets), len(windows), "있음" if api_key else "없음", sleep_sec)

    try:
        for index, target in enumerate(scope.targets, start=1):
            keyword = str(target.get("cpe_keyword") or target["canonical_name"])
            tokens = _product_tokens(target)
            collected_ids: set = set()
            rejected = 0

            for win_start, win_end in windows:
                start_index = 0
                while True:
                    params = {
                        "keywordSearch": keyword,
                        "lastModStartDate": _iso(win_start),
                        "lastModEndDate": _iso(win_end, end_of_day=True),
                        "resultsPerPage": per_page,
                        "startIndex": start_index,
                    }
                    data = client.get_json(API_URL, params=params)
                    time.sleep(sleep_sec)          # 레이트 리밋 준수

                    vulnerabilities = data.get("vulnerabilities") or []
                    for wrapper in vulnerabilities:
                        cve = wrapper.get("cve") or {}
                        cve_id = str(cve.get("id", "")).upper()
                        if not cve_id or cve_id in collected_ids:
                            continue
                        if str(cve.get("vulnStatus", "")).lower() == "rejected":
                            continue
                        relevant, reason = _is_relevant(cve, target, tokens)
                        if not relevant:
                            rejected += 1
                            log.debug("제외 %s ← %s (%s)",
                                      cve_id, target["canonical_name"], reason)
                            continue
                        collected_ids.add(cve_id)

                        score, vector, severity = _metrics(cve)
                        affected_range, fixed = _ranges_and_fixed(cve, tokens, range_max_len)
                        result.findings.append(Finding(
                            cve_id=cve_id,
                            sw_name=target["canonical_name"],
                            source="NVD",
                            vendor=_vendor(cve, tokens, target.get("vendor", "") or ""),
                            ecosystem=target.get("ecosystem", "other"),
                            affected_range=affected_range,
                            fixed_version=fixed,
                            severity=severity,
                            cvss_score=score,
                            cvss_vector=vector,
                            published_date=to_yyyymmdd(cve.get("published")),
                            modified_date=to_yyyymmdd(cve.get("lastModified")),
                            summary=_description(cve)[:summary_max_len * 2],
                            reference_url=_reference(cve),
                            collected_at=stamp,
                        ))

                    total = int(data.get("totalResults", 0))
                    start_index += len(vulnerabilities)
                    if start_index >= total or not vulnerabilities:
                        break

            log.info("[%d/%d] %s: %d건%s", index, len(scope.targets),
                     target["canonical_name"], len(collected_ids),
                     f" (관련 없어 제외 {rejected}건)" if rejected else "")

        log.info("NVD 수집 완료: %d건", len(result.findings))

    except SourceError as exc:
        result.ok = False
        result.error = str(exc)
        log.error("NVD 수집 실패 — 이 소스만 건너뜁니다: %s", exc)
    except Exception as exc:
        result.ok = False
        result.error = f"{type(exc).__name__}: {exc}"
        log.exception("NVD 수집 중 예상치 못한 오류")
    finally:
        result.requests_made = client.request_count
        result.elapsed_sec = time.time() - started
        client.close()
    return result


if __name__ == "__main__":
    from .base import print_findings, standalone_scope

    scope_obj, limit = standalone_scope("NVD 단독 수집")
    print(scope_obj.desc)
    print_findings(collect(scope_obj), limit)
