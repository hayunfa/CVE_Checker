"""SUMMARY 본문에서 버전 범위를 2차 추출한다.

소스(NVD/OSV/GHSA)가 구조화된 버전 정보를 주지 않아 AFFECTED_RANGE 가 '*' 로 남은 건만
대상으로, 영문 요약문에 **명시된 숫자**를 읽어 범위를 복원한다.

'*' 는 내부망 도구가 "모든 버전 영향" 으로 해석하기 때문에,
실제로는 영향 범위 밖인 버전까지 '사용불가' 로 잡히는 오탐이 생긴다.

── 안전 원칙 (이 순서로 지킨다) ────────────────────────────────
 1. 요약문에 **적혀 있는 숫자만** 쓴다. 브랜치 시작점 같은 걸 지어내지 않는다.
 2. 애매하면 **넓게** 잡는다. 좁히다 진짜 취약점을 놓치는 것보다,
    조금 넓게 잡아 사람이 한 번 더 보는 편이 낫다.
 3. 그래도 못 읽겠으면 '*' 를 그대로 둔다.

── 지원 표현 ──────────────────────────────────────────────────
    From A until B / from A to B      →  >=A,<B
    versions A - B / A through B      →  >=A,<=B
    before X / prior to X             →  <X
    through Y / up to (and including) Y →  <=Y
    A and earlier / A and below       →  <=A
    fixed in (version) C / patched in C / C and later →  FIXED_VERSION = C

    조치본이 여러 개인 경우 ("until 4.5.10 and 4.6.2") 는 브랜치 경계를 알 수 없으므로
    가장 높은 값을 상한으로 삼아 넓게 잡는다(원칙 2).
"""
from __future__ import annotations

import re
from typing import List, Optional, Sequence, Tuple

from .logutil import get_logger

log = get_logger("range")

# 버전 토큰: 1.2 / 1.2.3 / 1.2.3-rc1 / 2.0.0b1 …  (최소 한 번은 점을 포함해야 한다)
VERSION = r"\d+(?:\.\d+)+(?:[-.]?(?:rc|alpha|beta|dev|post|a|b)\d*)?"
# 뒤에 이어지는 글자가 있으면 버전이 아니다.
#   "2.32.x"  → 브랜치 표기이지 버전이 아니므로 '2.32' 로 잘라 읽으면 안 된다
#   "2025.11.14.mr64708.3" → 제품 빌드 문자열이지 버전 범위가 아니다
#   단, "0.26.0." 처럼 문장 끝 마침표는 허용해야 한다
_V = rf"v?({VERSION})(?!\.\w)(?!\w)"

# 버전처럼 보이지만 버전이 아닌 것들 (오탐 방지)
_NOT_VERSION_CONTEXT = re.compile(
    r"(?:python|node|java|php|ruby|go|cuda|ubuntu|debian|centos|rhel|windows|macos)"
    r"\s*$", re.I)


def _ver_key(version: str) -> tuple:
    """버전 비교용 키. 숫자 파트는 정수로, 사전 릴리스는 정식보다 낮게."""
    text = str(version).strip().lstrip("vV")
    parts = re.split(r"[.\-+]", text)
    key: List[tuple] = []
    for part in parts:
        if part.isdigit():
            key.append((1, int(part), ""))
        elif part:
            head = re.match(r"^(\d+)(.*)$", part)
            if head:
                key.append((1, int(head.group(1)), head.group(2)))
            else:
                key.append((0, 0, part))      # rc/alpha 등은 숫자보다 앞
    return tuple(key)


def _highest(versions: Sequence[str]) -> str:
    return max(versions, key=_ver_key) if versions else ""


def _clean(version: str) -> str:
    return str(version).strip().lstrip("vV").rstrip(".,;:)")


def _is_false_positive(text: str, start: int) -> bool:
    """'python 3.11' 처럼 다른 제품의 버전을 잡는 것을 막는다."""
    return bool(_NOT_VERSION_CONTEXT.search(text[max(0, start - 20):start]))


# ==========================================================================
#  패턴별 추출
# ==========================================================================
# "and 4.6.2", ", 2.31.5", ", and 2.32.1" 처럼 뒤따르는 추가 버전들.
# ", and X" 를 ", " 로만 읽으면 마지막 항목을 놓쳐 범위가 좁아진다(진짜 취약점을 놓침).
_TRAILING_AND = re.compile(
    rf"\s*(?:,\s*(?:and|or)\s+|,\s*|\s+(?:and|or)\s+|\s*&\s*){_V}", re.I)


def _collect_trailing(text: str, position: int) -> Tuple[List[str], int]:
    """'... 4.5.10 and 4.6.2' 의 뒤쪽 버전들을 모은다."""
    found: List[str] = []
    cursor = position
    while True:
        match = _TRAILING_AND.match(text, cursor)
        if not match:
            break
        found.append(_clean(match.group(1)))
        cursor = match.end()
    return found, cursor


# ---- 하한 + 상한 (구간) ----
_RANGE_PATTERNS = [
    # From A until B  /  from A up to B   → >=A,<B  (상한 제외)
    (re.compile(rf"\bfrom\s+{_V}\s+(?:until|up\s+to|to)\s+{_V}", re.I), "exclusive"),
    # versions A - B  /  A through B      → >=A,<=B (상한 포함)
    (re.compile(rf"\bversions?\s+{_V}\s*(?:-|–|—|through|thru)\s*{_V}", re.I), "inclusive"),
    (re.compile(rf"\b{_V}\s+through\s+{_V}", re.I), "inclusive"),
    (re.compile(rf"\bbetween\s+{_V}\s+and\s+{_V}", re.I), "inclusive"),
]

# ---- 상한만 ----
_UPPER_PATTERNS = [
    # before X / prior to X / earlier than X → <X
    (re.compile(rf"\b(?:before|prior\s+to|earlier\s+than|older\s+than)\s+{_V}", re.I), "<"),
    # through Y / up to and including Y → <=Y
    (re.compile(rf"\b(?:through|thru|up\s+to\s+and\s+including|up\s+to)\s+{_V}", re.I), "<="),
    # Y and earlier / Y and below / Y or earlier → <=Y
    (re.compile(rf"\b{_V}\s+(?:and|or)\s+(?:earlier|below|older|prior|before)", re.I), "<="),
]

# ---- 조치 버전 ----
_FIXED_PATTERNS = [
    re.compile(rf"\b(?:is\s+)?fixed\s+in\s+(?:versions?\s+)?{_V}", re.I),
    re.compile(rf"\b(?:has\s+been\s+)?patched\s+in\s+(?:versions?\s+)?{_V}", re.I),
    re.compile(rf"\bupgrade\s+to\s+(?:versions?\s+)?{_V}", re.I),
    re.compile(rf"\bupdate\s+to\s+(?:versions?\s+)?{_V}", re.I),
    re.compile(rf"\bresolved\s+in\s+(?:versions?\s+)?{_V}", re.I),
    re.compile(rf"\b{_V}\s+(?:and|or)\s+later\b", re.I),
    re.compile(rf"\b{_V}\s+(?:and|or)\s+(?:above|newer)\b", re.I),
]


def extract_fixed(text: str) -> Tuple[str, List[str]]:
    """조치 버전. (대표값, 발견된 전체 목록) — 대표값은 가장 낮은 것."""
    found: List[str] = []
    for pattern in _FIXED_PATTERNS:
        for match in pattern.finditer(text):
            if _is_false_positive(text, match.start()):
                continue
            found.append(_clean(match.group(1)))
            extra, _ = _collect_trailing(text, match.end())
            found.extend(extra)
    unique: List[str] = []
    for version in found:
        if version and version not in unique:
            unique.append(version)
    if not unique:
        return "", []
    # 조치 버전이 여러 개면 가장 낮은 것을 대표로 (가장 먼저 올려야 하는 버전)
    return min(unique, key=_ver_key), unique


def extract_ranges(text: str) -> List[str]:
    """요약문에서 범위식 목록을 뽑는다. 못 찾으면 빈 목록."""
    exprs: List[str] = []
    consumed: List[Tuple[int, int]] = []

    def overlaps(start: int, end: int) -> bool:
        return any(not (end <= s or start >= e) for s, e in consumed)

    # 1) 하한+상한 구간부터 (더 구체적인 정보라 우선)
    for pattern, bound in _RANGE_PATTERNS:
        for match in pattern.finditer(text):
            if _is_false_positive(text, match.start()) or overlaps(*match.span()):
                continue
            low, high = _clean(match.group(1)), _clean(match.group(2))
            extra, end = _collect_trailing(text, match.end())
            if extra:
                # "until 4.5.10 and 4.6.2" — 브랜치 경계를 알 수 없으므로
                # 가장 높은 조치본을 상한으로 삼아 넓게 잡는다(놓치지 않는 쪽).
                high = _highest([high] + extra)
            if _ver_key(low) >= _ver_key(high) and bound == "exclusive":
                continue                       # 하한이 상한 이상이면 해석 실패
            operator = "<" if bound == "exclusive" else "<="
            exprs.append(f">={low},{operator}{high}")
            consumed.append((match.start(), max(end, match.end())))

    # 2) 상한만 있는 표현
    for pattern, operator in _UPPER_PATTERNS:
        for match in pattern.finditer(text):
            if _is_false_positive(text, match.start()) or overlaps(*match.span()):
                continue
            high = _clean(match.group(1))
            extra, end = _collect_trailing(text, match.end())
            if extra:
                high = _highest([high] + extra)
            exprs.append(f"{operator}{high}")
            consumed.append((match.start(), max(end, match.end())))

    # 중복 제거 (순서 유지)
    unique: List[str] = []
    for expr in exprs:
        if expr not in unique:
            unique.append(expr)
    return unique


def recover_from_summary(summary: str,
                         range_max_len: int = 500) -> Tuple[Optional[str], str]:
    """요약문에서 (범위식, 조치버전) 을 복원한다. 실패하면 (None, "").

    >>> recover_from_summary("From 0.19.0 until 0.26.0, ... fixed in version 0.26.0.")
    ('>=0.19.0,<0.26.0', '0.26.0')
    """
    from .normalize import join_ranges          # 순환 참조 방지를 위해 지연 임포트

    if not summary or not summary.strip():
        return None, ""

    exprs = extract_ranges(summary)
    fixed, _ = extract_fixed(summary)

    if not exprs:
        # 범위는 못 찾았는데 조치 버전만 나온 경우 → 그 미만을 영향 범위로 본다
        if fixed:
            return join_ranges([f"<{fixed}"], range_max_len), fixed
        return None, ""

    return join_ranges(exprs, range_max_len), fixed


# ==========================================================================
#  파이프라인 연결
# ==========================================================================
def recover_missing_ranges(findings, range_max_len: int = 500,
                           summary_max_len: int = 1000) -> int:
    """AFFECTED_RANGE 가 '*' 인 건만 골라 요약문에서 범위를 복원한다.

    성공하면 SUMMARY 앞의 '[버전범위 불명확] ' 표시를 뗀다.
    돌려주는 값: 복원에 성공한 건수.
    """
    from .normalize import (
        ALL_VERSIONS,
        RANGE_UNCERTAIN_PREFIX,
        clean_summary,
        clean_version,
    )

    recovered = 0
    for finding in findings:
        if (finding.affected_range or ALL_VERSIONS) != ALL_VERSIONS:
            continue                            # 이미 범위가 있으면 건드리지 않는다

        # 번역 전이라 summary 가 영문이지만, 안전하게 원문 쪽을 우선 본다
        source_text = finding.summary_en or finding.summary or ""
        body = source_text
        if body.startswith(RANGE_UNCERTAIN_PREFIX):
            body = body[len(RANGE_UNCERTAIN_PREFIX):]

        expr, fixed = recover_from_summary(body, range_max_len)
        if not expr or expr == ALL_VERSIONS:
            continue

        finding.affected_range = expr
        if fixed and not finding.fixed_version:
            finding.fixed_version = clean_version(fixed)

        # 범위를 찾았으니 '불명확' 표시를 뗀다
        for field in ("summary", "summary_en"):
            value = getattr(finding, field, "") or ""
            if value.startswith(RANGE_UNCERTAIN_PREFIX):
                setattr(finding, field,
                        clean_summary(value[len(RANGE_UNCERTAIN_PREFIX):],
                                      summary_max_len))
        recovered += 1
        log.debug("범위 복원 %s (%s): %s  fixed=%s",
                  finding.cve_id, finding.sw_name, expr, fixed or "-")

    if recovered:
        log.info("요약문에서 버전 범위 복원: %d건", recovered)
    return recovered


if __name__ == "__main__":
    import sys

    text = " ".join(sys.argv[1:]) or (
        "vLLM is an inference engine. From 0.19.0 until 0.26.0, the /v1/completions "
        "field accepts an unbounded list. This issue is fixed in version 0.26.0.")
    print(f"[원문] {text}\n")
    print(f"[범위] {recover_from_summary(text)}")
