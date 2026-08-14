"""소스별 결과 → 공통 스키마 정규화 + 버전범위 표기 변환.

★ 가장 중요한 부분: 내부망 VersionRange.java 가 파싱할 문자열을 만든다.

    문법 :  ','  = AND      '|' = OR      연산자: >= > <= < ==      전체영향 = '*'
    예시 :  ">=1.0.0,<1.4.2"
            ">=2.0.0,<2.3.1|>=3.0.0,<3.0.4"
            "==1.2.3"
            "<2.6.0"
            "*"

규칙
  - 출력 문자열에 공백을 절대 넣지 않는다.
  - introduced == "0" 이면 하한을 생략한다 ( ">=0,<1.4.2" → "<1.4.2" ).
  - 범위를 도출할 수 없으면 "*" 를 쓰고 SUMMARY 앞에 "[버전범위 불명확] " 을 붙인다.
  - 길이가 range_max_len(기본 500)을 넘으면 대표 범위만 남기고 절삭한다.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .logutil import get_logger
from .scope import SEVERITY_RANK

log = get_logger("normalize")

RANGE_UNCERTAIN_PREFIX = "[버전범위 불명확] "
ALL_VERSIONS = "*"
DEFAULT_RANGE_MAX_LEN = 500
DEFAULT_SUMMARY_MAX_LEN = 1000

# 버전범위·조치버전은 OSV 가 가장 정확하다
RANGE_PRIORITY = {"OSV": 0, "GHSA": 1, "NVD": 2, "KEV": 9}
# CVSS·요약은 NVD 가 가장 정확하다
INFO_PRIORITY = {"NVD": 0, "GHSA": 1, "OSV": 2, "KEV": 9}
# SOURCE 컬럼 표기 순서 (병합 시 "NVD+OSV")
SOURCE_ORDER = ("NVD", "OSV", "GHSA", "KEV")

# 하한이 '전체 처음'을 뜻하는 값들
_ZERO_TOKENS = {"0", "0.0", "0.0.0", "", "*", "-", "none"}


# ==========================================================================
#  1. 버전 문자열 다루기
# ==========================================================================
def clean_version(value: Any) -> str:
    """버전 문자열에서 공백·따옴표를 제거한다."""
    if value is None:
        return ""
    text = str(value).strip().strip('"').strip("'")
    return re.sub(r"\s+", "", text)


def _is_zero(value: str) -> bool:
    return clean_version(value).lower() in _ZERO_TOKENS


def bounds_to_expr(start_including: Any = None,
                   start_excluding: Any = None,
                   end_including: Any = None,
                   end_excluding: Any = None,
                   exact: Any = None) -> str:
    """상·하한 값들을 하나의 AND 식으로 조립한다.

    >>> bounds_to_expr(start_including="1.0", end_excluding="1.4.2")
    '>=1.0,<1.4.2'
    >>> bounds_to_expr(start_including="0", end_excluding="1.4.2")
    '<1.4.2'
    >>> bounds_to_expr(exact="1.2.3")
    '==1.2.3'
    >>> bounds_to_expr()
    '*'
    """
    exact_v = clean_version(exact)
    if exact_v and not _is_zero(exact_v):
        return f"=={exact_v}"

    parts: List[str] = []

    se = clean_version(start_excluding)
    si = clean_version(start_including)
    if se and not _is_zero(se):
        parts.append(f">{se}")
    elif si and not _is_zero(si):
        parts.append(f">={si}")

    ee = clean_version(end_excluding)
    ei = clean_version(end_including)
    if ee and not _is_zero(ee):
        parts.append(f"<{ee}")
    elif ei and not _is_zero(ei):
        parts.append(f"<={ei}")

    if not parts:
        return ALL_VERSIONS
    return ",".join(parts)


def truncate_range(expr: str, max_len: int = DEFAULT_RANGE_MAX_LEN) -> str:
    """길이 초과 시 대표 범위(앞쪽 OR 블록)만 남긴다."""
    if not expr:
        return ALL_VERSIONS
    if len(expr) <= max_len:
        return expr
    kept: List[str] = []
    total = 0
    for part in expr.split("|"):
        add = len(part) + (1 if kept else 0)
        if total + add > max_len:
            break
        kept.append(part)
        total += add
    if not kept:  # 첫 블록 하나도 너무 길면 통째로 포기
        return ALL_VERSIONS
    return "|".join(kept)


def join_ranges(exprs: Iterable[str],
                max_len: int = DEFAULT_RANGE_MAX_LEN) -> str:
    """여러 affected 블록을 '|' 로 잇는다. 중복 제거, 공백 제거, 길이 절삭."""
    seen: List[str] = []
    for raw in exprs or []:
        expr = re.sub(r"\s+", "", str(raw or ""))
        if not expr:
            continue
        if expr not in seen:
            seen.append(expr)
    concrete = [e for e in seen if e != ALL_VERSIONS]
    if concrete:                      # 구체적 범위가 하나라도 있으면 '*' 는 버린다
        seen = concrete
    if not seen:
        return ALL_VERSIONS
    return truncate_range("|".join(seen), max_len)


def is_uncertain(expr: str) -> bool:
    return not expr or expr == ALL_VERSIONS


# ==========================================================================
#  2. 소스별 → 범위식 변환
# ==========================================================================
def osv_events_to_exprs(events: Sequence[Dict[str, Any]]) -> List[str]:
    """OSV ranges[].events 를 범위식 목록으로.

    events 는 순서가 있는 이벤트열이다:
      [{"introduced":"0"},{"fixed":"1.4.2"}]              → ["<1.4.2"]
      [{"introduced":"1.0"},{"fixed":"1.4.2"},
       {"introduced":"2.0"},{"fixed":"2.1.0"}]            → [">=1.0,<1.4.2", ">=2.0,<2.1.0"]
      [{"introduced":"1.0"},{"last_affected":"1.4.1"}]    → [">=1.0,<=1.4.1"]
      [{"introduced":"1.0"}]                              → [">=1.0"]
    """
    exprs: List[str] = []
    current: Optional[str] = None
    opened = False

    def flush(end_incl: Any = None, end_excl: Any = None) -> None:
        nonlocal current, opened
        expr = bounds_to_expr(start_including=current,
                              end_including=end_incl,
                              end_excluding=end_excl)
        exprs.append(expr)
        current, opened = None, False

    for event in events or []:
        if not isinstance(event, dict):
            continue
        if "introduced" in event:
            if opened:                       # 상한 없이 다음 구간이 시작 → 열린 구간 마감
                flush()
            current = event.get("introduced")
            opened = True
        elif "fixed" in event:
            flush(end_excl=event.get("fixed"))
        elif "last_affected" in event:
            flush(end_incl=event.get("last_affected"))
        elif "limit" in event:
            limit = clean_version(event.get("limit"))
            if limit in ("*", ""):
                flush()
            else:
                flush(end_excl=limit)
    if opened:
        flush()
    return exprs


def osv_affected_to_exprs(affected: Dict[str, Any]) -> List[str]:
    """OSV affected 블록 1개 → 범위식 목록. ranges 우선, 없으면 versions 열거."""
    exprs: List[str] = []
    for rng in affected.get("ranges") or []:
        if not isinstance(rng, dict):
            continue
        if str(rng.get("type", "")).upper() == "GIT":
            continue                      # 커밋 해시는 버전이 아니므로 제외
        exprs.extend(osv_events_to_exprs(rng.get("events") or []))

    concrete = [e for e in exprs if e != ALL_VERSIONS]
    if concrete:
        return concrete

    versions = [clean_version(v) for v in (affected.get("versions") or [])]
    versions = [v for v in versions if v]
    if versions:
        return [f"=={v}" for v in versions]
    return exprs or []


def osv_fixed_version(affected: Dict[str, Any]) -> str:
    """OSV affected 블록에서 최초 조치(fixed) 버전 1개."""
    for rng in affected.get("ranges") or []:
        if not isinstance(rng, dict) or str(rng.get("type", "")).upper() == "GIT":
            continue
        for event in rng.get("events") or []:
            if isinstance(event, dict) and event.get("fixed"):
                return clean_version(event["fixed"])
    return ""


_GHSA_TOKEN = re.compile(r"^(>=|<=|==|=|>|<)?\s*(.+)$")


def ghsa_range_to_expr(text: Any) -> str:
    """GHSA vulnerableVersionRange → 범위식.

    "< 2.6.0"              → "<2.6.0"
    ">= 1.0.0, < 1.4.2"    → ">=1.0.0,<1.4.2"
    "= 1.2.3"              → "==1.2.3"
    ""                     → "*"
    """
    if not text:
        return ALL_VERSIONS
    parts: List[str] = []
    for chunk in str(text).split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        match = _GHSA_TOKEN.match(chunk)
        if not match:
            continue
        operator, version = match.group(1), clean_version(match.group(2))
        if not version or version == "*":
            continue
        if operator in (None, "", "="):
            operator = "=="
        parts.append(f"{operator}{version}")
    if not parts:
        return ALL_VERSIONS
    return ",".join(parts)


_CPE_VERSION_FIELD = 5


def nvd_cpe_match_to_expr(cpe_match: Dict[str, Any]) -> str:
    """NVD configurations[].nodes[].cpeMatch 항목 1개 → 범위식.

    versionStartIncluding=1.0, versionEndExcluding=1.4.2 → ">=1.0,<1.4.2"
    경계값이 하나도 없으면 CPE 문자열의 version 필드를 본다.
    """
    expr = bounds_to_expr(
        start_including=cpe_match.get("versionStartIncluding"),
        start_excluding=cpe_match.get("versionStartExcluding"),
        end_including=cpe_match.get("versionEndIncluding"),
        end_excluding=cpe_match.get("versionEndExcluding"),
    )
    if expr != ALL_VERSIONS:
        return expr

    criteria = str(cpe_match.get("criteria") or cpe_match.get("cpe23Uri") or "")
    fields = criteria.split(":")
    if len(fields) > _CPE_VERSION_FIELD:
        version = clean_version(fields[_CPE_VERSION_FIELD])
        if version and version not in ("*", "-"):
            return f"=={version}"
    return ALL_VERSIONS


# ==========================================================================
#  3. 심각도 / 날짜 / 문자열
# ==========================================================================
def severity_from_score(score: Optional[float]) -> str:
    """CVSS v3.1 base score → 심각도 등급."""
    if score is None:
        return "NONE"
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "NONE"
    if value >= 9.0:
        return "CRITICAL"
    if value >= 7.0:
        return "HIGH"
    if value >= 4.0:
        return "MEDIUM"
    if value >= 0.1:
        return "LOW"
    return "NONE"


_CVSS31_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}


def _cvss_roundup(value: float) -> float:
    """CVSS v3.1 규격의 Roundup (소수 첫째자리로 올림)."""
    integer = int(round(value * 100000))
    if integer % 10000 == 0:
        return integer / 100000.0
    return (int(integer / 10000) + 1) / 10.0


def cvss31_base_score(vector: Any) -> Optional[float]:
    """CVSS v3.x 벡터 문자열 → base score.

    OSV·GHSA 는 점수 없이 벡터만 주는 경우가 많아 직접 계산한다.
    v3 이 아니거나 필수 항목이 빠지면 None.
    """
    if not vector:
        return None
    text = str(vector).strip()
    if not text.upper().startswith("CVSS:3"):
        return None

    metrics: Dict[str, str] = {}
    for chunk in text.split("/")[1:]:
        if ":" in chunk:
            key, _, value = chunk.partition(":")
            metrics[key.strip().upper()] = value.strip().upper()

    required = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if any(key not in metrics for key in required):
        return None

    scope_changed = metrics["S"] == "C"
    try:
        av = _CVSS31_WEIGHTS["AV"][metrics["AV"]]
        ac = _CVSS31_WEIGHTS["AC"][metrics["AC"]]
        ui = _CVSS31_WEIGHTS["UI"][metrics["UI"]]
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
        conf = _CVSS31_WEIGHTS["C"][metrics["C"]]
        integ = _CVSS31_WEIGHTS["I"][metrics["I"]]
        avail = _CVSS31_WEIGHTS["A"][metrics["A"]]
    except KeyError:
        return None

    iss = 1 - ((1 - conf) * (1 - integ) * (1 - avail))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    total = impact + exploitability
    if scope_changed:
        total *= 1.08
    return _cvss_roundup(min(total, 10.0))


def severity_from_text(text: Any) -> str:
    """소스가 준 severity 문자열 → 규격 등급."""
    if not text:
        return "NONE"
    value = str(text).strip().upper()
    aliases = {"MODERATE": "MEDIUM", "IMPORTANT": "HIGH", "SEVERE": "CRITICAL"}
    value = aliases.get(value, value)
    return value if value in SEVERITY_RANK else "NONE"


def to_yyyymmdd(value: Any) -> str:
    """ISO 날짜/일시 → 'YYYYMMDD'. 알아볼 수 없으면 빈 문자열."""
    if not value:
        return ""
    text = str(value).strip()
    match = re.match(r"(\d{4})-?(\d{2})-?(\d{2})", text)
    if match:
        return "".join(match.groups())
    return ""


def clean_summary(text: Any, max_len: int = DEFAULT_SUMMARY_MAX_LEN,
                  prefix: str = "") -> str:
    """개행·탭을 공백으로 바꾸고 길이를 맞춘다."""
    body = re.sub(r"\s+", " ", str(text or "")).strip()
    if prefix and not body.startswith(prefix):
        body = prefix + body
    if len(body) > max_len:
        body = body[:max_len]
    return body


def normalize_score(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        score = round(float(value), 1)
    except (TypeError, ValueError):
        return None
    if score < 0 or score > 10:
        return None
    return score


# ==========================================================================
#  4. 공통 스키마
# ==========================================================================
@dataclass
class Finding:
    """소스 1곳에서 얻은 (CVE, S/W) 1건. 병합 전 원자료."""

    cve_id: str
    sw_name: str                       # ★ 반드시 watchlist 의 canonical_name
    source: str                        # NVD / OSV / GHSA
    vendor: str = ""
    ecosystem: str = "other"
    affected_range: str = ALL_VERSIONS
    fixed_version: str = ""
    severity: str = "NONE"
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    published_date: str = ""           # YYYYMMDD
    modified_date: str = ""            # YYYYMMDD
    kev_yn: str = "N"
    summary: str = ""
    reference_url: str = ""
    collected_at: str = ""             # YYYYMMDDHHmmss
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data.pop("extra", None)
        return data


def _pick(findings: Sequence[Finding], priority: Dict[str, int],
          getter, accept=lambda v: bool(v)):
    """우선순위가 높은 소스부터 훑어 조건을 만족하는 첫 값을 돌려준다."""
    for finding in sorted(findings, key=lambda f: priority.get(f.source.upper(), 50)):
        value = getter(finding)
        if accept(value):
            return value
    return None


def merge_findings(findings: Sequence[Finding],
                   kev_ids: Optional[set] = None,
                   watch_index: Optional[Dict[str, Dict[str, Any]]] = None,
                   range_max_len: int = DEFAULT_RANGE_MAX_LEN,
                   summary_max_len: int = DEFAULT_SUMMARY_MAX_LEN) -> List[Finding]:
    """동일 (CVE_ID, SW_NAME) 을 1건으로 병합한다.

    버전범위·조치버전 : OSV > GHSA > NVD
    CVSS·요약        : NVD > GHSA > OSV
    """
    kev_ids = kev_ids or set()
    watch_index = watch_index or {}

    groups: Dict[tuple, List[Finding]] = {}
    for finding in findings:
        if not finding.cve_id or not finding.sw_name:
            continue
        groups.setdefault((finding.cve_id.upper(), finding.sw_name), []).append(finding)

    merged: List[Finding] = []
    for (cve_id, sw_name), items in groups.items():
        watch = watch_index.get(sw_name, {})

        # --- 버전범위 / 조치버전 : OSV > GHSA > NVD, 단 '*' 보다 구체적 범위 우선 ---
        affected = _pick(items, RANGE_PRIORITY,
                         lambda f: f.affected_range,
                         lambda v: bool(v) and v != ALL_VERSIONS) or ALL_VERSIONS
        affected = join_ranges([affected], range_max_len)
        fixed = _pick(items, RANGE_PRIORITY, lambda f: clean_version(f.fixed_version)) or ""

        # --- CVSS / 요약 : NVD > GHSA > OSV ---
        score = _pick(items, INFO_PRIORITY,
                      lambda f: f.cvss_score, lambda v: v is not None)
        vector = _pick(items, INFO_PRIORITY, lambda f: f.cvss_vector) or ""
        summary_raw = _pick(items, INFO_PRIORITY, lambda f: f.summary) or ""
        reference = _pick(items, INFO_PRIORITY, lambda f: f.reference_url) or ""

        if score is not None:
            severity = severity_from_score(score)
        else:                              # 점수가 없으면 소스가 준 등급 중 가장 높은 것
            severity = max((f.severity or "NONE" for f in items),
                           key=lambda s: SEVERITY_RANK.get(s, 0), default="NONE")

        published = _pick(items, INFO_PRIORITY, lambda f: f.published_date) or ""
        modified = max((f.modified_date for f in items if f.modified_date), default="")

        sources = [s for s in SOURCE_ORDER
                   if s in {f.source.upper() for f in items}]
        collected = max((f.collected_at for f in items if f.collected_at), default="")

        prefix = RANGE_UNCERTAIN_PREFIX if is_uncertain(affected) else ""
        merged.append(Finding(
            cve_id=cve_id,
            sw_name=sw_name,
            source="+".join(sources) or "NVD",
            vendor=(_pick(items, INFO_PRIORITY, lambda f: f.vendor)
                    or watch.get("vendor", "") or ""),
            ecosystem=(watch.get("ecosystem")
                       or _pick(items, INFO_PRIORITY, lambda f: f.ecosystem) or "other"),
            affected_range=affected,
            fixed_version=fixed,
            severity=severity,
            cvss_score=normalize_score(score),
            cvss_vector=vector,
            published_date=published,
            modified_date=modified or published,
            kev_yn="Y" if cve_id.upper() in kev_ids else "N",
            summary=clean_summary(summary_raw, summary_max_len, prefix),
            reference_url=reference,
            collected_at=collected,
        ))
    return merged


def filter_by_severity(findings: Sequence[Finding], scope) -> List[Finding]:
    """심각도 하한 필터. KEV 등재 건은 심각도와 무관하게 항상 남긴다."""
    kept: List[Finding] = []
    for finding in findings:
        if scope.severity_allowed(finding.severity, kev=(finding.kev_yn == "Y")):
            kept.append(finding)
    return kept


def sort_findings(findings: Sequence[Finding]) -> List[Finding]:
    """SEVERITY(CRITICAL→NONE) → CVSS_SCORE 내림차순 → SW_NAME → CVE_ID."""
    return sorted(
        findings,
        key=lambda f: (
            -SEVERITY_RANK.get((f.severity or "NONE").upper(), 0),
            -(f.cvss_score if f.cvss_score is not None else -1.0),
            (f.sw_name or "").lower(),
            f.cve_id or "",
        ),
    )


def build_watch_index(targets: Sequence[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """canonical_name → watchlist 항목."""
    return {t["canonical_name"]: t for t in targets}


def build_alias_index(targets: Sequence[Dict[str, Any]]) -> Dict[str, str]:
    """원본 패키지명(소문자) → canonical_name.  SW_NAME 정규화용."""
    index: Dict[str, str] = {}
    for item in targets:
        canonical = item["canonical_name"]
        keys = {canonical.lower()}
        keys |= {str(a).lower() for a in (item.get("aliases") or [])}
        for key in ("pypi", "npm", "go", "github", "cpe_keyword"):
            value = item.get(key)
            if value:
                index.setdefault(str(value).lower(), canonical)
        for key in keys:
            index[key] = canonical
    return index


def resolve_canonical(name: Any, alias_index: Dict[str, str]) -> Optional[str]:
    """소스가 준 패키지명을 canonical_name 으로 바꾼다. 못 찾으면 None."""
    if not name:
        return None
    key = str(name).strip().lower()
    if key in alias_index:
        return alias_index[key]
    # 'github.com/owner/repo' 형태 보정
    if key.startswith("github.com/"):
        short = key[len("github.com/"):]
        if short in alias_index:
            return alias_index[short]
    return None
