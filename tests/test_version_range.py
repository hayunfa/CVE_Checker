"""버전범위 표기 변환 검증 (양방향).

방향 1 : 소스 원자료(OSV/NVD/GHSA) → 범위 문자열   (생성 검증)
방향 2 : 범위 문자열 → 특정 버전 포함 여부         (의미 검증)

방향 2 는 내부망 VersionRange.java 와 동일한 문법 해석기를 테스트 안에 두고,
"이 범위에 1.4.1 은 들어가고 1.4.2 는 빠진다" 를 확인한다.
문자열만 맞추고 의미가 틀리는 사고를 막기 위한 장치다.
"""
from __future__ import annotations

import re

import pytest

from src.aicve.normalize import (
    ALL_VERSIONS,
    bounds_to_expr,
    clean_version,
    ghsa_range_to_expr,
    is_uncertain,
    join_ranges,
    nvd_cpe_match_to_expr,
    osv_affected_to_exprs,
    osv_events_to_exprs,
    osv_fixed_version,
    truncate_range,
)

# ==========================================================================
#  참조 해석기 — 내부망 VersionRange.java 와 같은 문법을 해석한다
# ==========================================================================
_TERM = re.compile(r"^(>=|<=|==|>|<)(.+)$")


def _key(version: str):
    """비교용 키. 숫자 파트는 정수로, 나머지는 문자열로."""
    parts = re.split(r"[.\-+]", version)
    key = []
    for part in parts:
        if part.isdigit():
            key.append((1, int(part), ""))
        elif part:
            head = re.match(r"^(\d+)", part)
            if head:
                key.append((1, int(head.group(1)), part[head.end():]))
            else:
                key.append((0, 0, part))       # rc/alpha 등은 숫자보다 앞
    return key


def _cmp(a: str, b: str) -> int:
    ka, kb = _key(a), _key(b)
    size = max(len(ka), len(kb))
    ka += [(1, 0, "")] * (size - len(ka))
    kb += [(1, 0, "")] * (size - len(kb))
    return (ka > kb) - (ka < kb)


def matches(expr: str, version: str) -> bool:
    """범위식에 해당 버전이 포함되는지. ',' = AND, '|' = OR, '*' = 전체."""
    assert " " not in expr, f"범위식에 공백이 있으면 안 된다: {expr!r}"
    if expr == ALL_VERSIONS:
        return True
    for or_block in expr.split("|"):
        ok = True
        for term in or_block.split(","):
            match = _TERM.match(term)
            assert match, f"해석할 수 없는 항: {term!r} (전체: {expr!r})"
            operator, bound = match.group(1), match.group(2)
            result = _cmp(version, bound)
            if operator == ">=" and not result >= 0:
                ok = False
            elif operator == ">" and not result > 0:
                ok = False
            elif operator == "<=" and not result <= 0:
                ok = False
            elif operator == "<" and not result < 0:
                ok = False
            elif operator == "==" and result != 0:
                ok = False
            if not ok:
                break
        if ok:
            return True
    return False


# ==========================================================================
#  방향 1 — OSV events → 범위식
# ==========================================================================
OSV_CASES = [
    # (설명, events, 기대 범위식)
    ("introduced=0 + fixed → 하한 축약",
     [{"introduced": "0"}, {"fixed": "1.4.2"}], "<1.4.2"),
    ("introduced + fixed",
     [{"introduced": "1.0.0"}, {"fixed": "1.4.2"}], ">=1.0.0,<1.4.2"),
    ("introduced 만 있음 (미조치)",
     [{"introduced": "2.1.0"}], ">=2.1.0"),
    ("introduced=0 만 있음 → 전체 영향",
     [{"introduced": "0"}], "*"),
    ("last_affected → 이하 연산자",
     [{"introduced": "1.0.0"}, {"last_affected": "1.4.1"}], ">=1.0.0,<=1.4.1"),
    ("introduced=0 + last_affected",
     [{"introduced": "0"}, {"last_affected": "0.9.9"}], "<=0.9.9"),
    ("limit → 미만 연산자",
     [{"introduced": "1.0.0"}, {"limit": "2.0.0"}], ">=1.0.0,<2.0.0"),
    ("limit=* → 상한 없음",
     [{"introduced": "1.0.0"}, {"limit": "*"}], ">=1.0.0"),
    ("빈 events",
     [], None),
]


@pytest.mark.parametrize("desc, events, expected", OSV_CASES)
def test_osv_events(desc, events, expected):
    result = osv_events_to_exprs(events)
    if expected is None:
        assert result == [], desc
    else:
        assert result == [expected], desc


def test_osv_events_multi_branch():
    """여러 구간 → '|' 로 연결된다."""
    events = [
        {"introduced": "2.0.0"}, {"fixed": "2.3.1"},
        {"introduced": "3.0.0"}, {"fixed": "3.0.4"},
    ]
    exprs = osv_events_to_exprs(events)
    assert exprs == [">=2.0.0,<2.3.1", ">=3.0.0,<3.0.4"]
    assert join_ranges(exprs) == ">=2.0.0,<2.3.1|>=3.0.0,<3.0.4"


def test_osv_events_reopen_without_fix():
    """상한 없이 다음 introduced 가 나오면 앞 구간은 열린 채로 마감된다."""
    events = [{"introduced": "1.0.0"}, {"introduced": "2.0.0"}, {"fixed": "2.5.0"}]
    assert osv_events_to_exprs(events) == [">=1.0.0", ">=2.0.0,<2.5.0"]


def test_osv_affected_git_range_ignored():
    """GIT 타입(커밋 해시)은 버전이 아니므로 무시한다."""
    affected = {
        "ranges": [
            {"type": "GIT", "events": [{"introduced": "abc123"}, {"fixed": "def456"}]},
            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.0"}]},
        ]
    }
    assert osv_affected_to_exprs(affected) == ["<1.2.0"]


def test_osv_affected_versions_fallback():
    """ranges 가 없으면 versions 목록을 '==' 로 열거한다."""
    affected = {"versions": ["1.0.0", "1.0.1"]}
    assert osv_affected_to_exprs(affected) == ["==1.0.0", "==1.0.1"]
    assert join_ranges(osv_affected_to_exprs(affected)) == "==1.0.0|==1.0.1"


def test_osv_fixed_version():
    affected = {"ranges": [{"type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "1.4.2"}]}]}
    assert osv_fixed_version(affected) == "1.4.2"
    assert osv_fixed_version({"ranges": []}) == ""


# ==========================================================================
#  방향 1 — NVD cpeMatch → 범위식
# ==========================================================================
NVD_CASES = [
    ("시작 포함 + 종료 제외",
     {"versionStartIncluding": "1.0", "versionEndExcluding": "1.4.2"}, ">=1.0,<1.4.2"),
    ("시작 제외 + 종료 포함",
     {"versionStartExcluding": "1.0", "versionEndIncluding": "1.4.2"}, ">1.0,<=1.4.2"),
    ("종료 제외만",
     {"versionEndExcluding": "2.6.0"}, "<2.6.0"),
    ("종료 포함만",
     {"versionEndIncluding": "2.6.0"}, "<=2.6.0"),
    ("시작 포함만",
     {"versionStartIncluding": "3.0.0"}, ">=3.0.0"),
    ("경계 없음 + CPE 에 구체 버전 → 정확히 그 버전",
     {"criteria": "cpe:2.3:a:pytorch:pytorch:2.1.0:*:*:*:*:*:*:*"}, "==2.1.0"),
    ("경계 없음 + CPE version=* → 전체 영향",
     {"criteria": "cpe:2.3:a:pytorch:pytorch:*:*:*:*:*:*:*:*"}, "*"),
    ("경계 없음 + CPE version=- → 전체 영향",
     {"criteria": "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*"}, "*"),
    ("아무 정보 없음",
     {}, "*"),
    ("시작이 0 이면 하한 생략",
     {"versionStartIncluding": "0", "versionEndExcluding": "1.0.0"}, "<1.0.0"),
]


@pytest.mark.parametrize("desc, cpe, expected", NVD_CASES)
def test_nvd_cpe_match(desc, cpe, expected):
    assert nvd_cpe_match_to_expr(cpe) == expected, desc


# ==========================================================================
#  방향 1 — GHSA vulnerableVersionRange → 범위식
# ==========================================================================
GHSA_CASES = [
    ("미만 (공백 제거)", "< 2.6.0", "<2.6.0"),
    ("이상+미만", ">= 1.0.0, < 1.4.2", ">=1.0.0,<1.4.2"),
    ("단일 등호 → ==", "= 1.2.3", "==1.2.3"),
    ("이하", "<= 3.1.4", "<=3.1.4"),
    ("초과", "> 0.9.0", ">0.9.0"),
    ("이상만", ">= 4.0.0", ">=4.0.0"),
    ("공백 없는 입력 그대로", ">=1.0.0,<2.0.0", ">=1.0.0,<2.0.0"),
    ("연산자 없는 버전 → ==", "1.2.3", "==1.2.3"),
    ("빈 문자열 → 전체", "", "*"),
    ("None → 전체", None, "*"),
    ("이미 == 인 경우", "== 5.0.0", "==5.0.0"),
    ("rc 버전", "< 1.0.0-rc2", "<1.0.0-rc2"),
]


@pytest.mark.parametrize("desc, raw, expected", GHSA_CASES)
def test_ghsa_range(desc, raw, expected):
    assert ghsa_range_to_expr(raw) == expected, desc


# ==========================================================================
#  방향 1 — bounds_to_expr 직접 검증
# ==========================================================================
BOUNDS_CASES = [
    ("정확히 한 버전", dict(exact="1.2.3"), "==1.2.3"),
    ("하한만", dict(start_including="1.0"), ">=1.0"),
    ("상한만", dict(end_excluding="2.0"), "<2.0"),
    ("양쪽", dict(start_including="1.0", end_including="2.0"), ">=1.0,<=2.0"),
    ("하한 0 은 생략", dict(start_including="0.0.0", end_excluding="1.0"), "<1.0"),
    ("아무것도 없음", dict(), "*"),
    ("따옴표·공백 제거", dict(start_including=' "1.0.0" '), ">=1.0.0"),
    ("제외 하한이 포함 하한보다 우선", dict(start_including="1.0", start_excluding="1.1"), ">1.1"),
    ("제외 상한이 포함 상한보다 우선", dict(end_including="2.0", end_excluding="1.9"), "<1.9"),
]


@pytest.mark.parametrize("desc, kwargs, expected", BOUNDS_CASES)
def test_bounds(desc, kwargs, expected):
    assert bounds_to_expr(**kwargs) == expected, desc


# ==========================================================================
#  join / truncate / 공백 금지
# ==========================================================================
def test_join_dedup_and_or():
    assert join_ranges(["<1.0", "<1.0", ">=2.0"]) == "<1.0|>=2.0"


def test_join_drops_star_when_concrete_exists():
    assert join_ranges(["*", ">=1.0,<2.0"]) == ">=1.0,<2.0"


def test_join_empty_is_star():
    assert join_ranges([]) == ALL_VERSIONS
    assert join_ranges(["", None]) == ALL_VERSIONS


def test_join_removes_whitespace():
    assert join_ranges([">= 1.0 , < 2.0"]) == ">=1.0,<2.0"


def test_truncate_keeps_leading_blocks():
    blocks = [f">={i}.0.0,<{i}.9.9" for i in range(1, 60)]
    expr = join_ranges(blocks, max_len=100)
    assert len(expr) <= 100
    assert expr.startswith(">=1.0.0,<1.9.9")
    assert not expr.endswith("|")


def test_truncate_short_expr_untouched():
    assert truncate_range(">=1.0,<2.0", 500) == ">=1.0,<2.0"


def test_no_space_in_any_output():
    """모든 변환 결과에 공백이 없어야 한다 (내부망 파서 규격)."""
    outputs = [
        ghsa_range_to_expr(">= 1.0.0 , < 2.0.0"),
        nvd_cpe_match_to_expr({"versionStartIncluding": " 1.0 ",
                               "versionEndExcluding": " 2.0 "}),
        join_ranges(osv_events_to_exprs([{"introduced": " 1.0 "}, {"fixed": " 2.0 "}])),
        bounds_to_expr(exact=" 1.2.3 "),
    ]
    for expr in outputs:
        assert " " not in expr, expr


def test_clean_version():
    assert clean_version(' "1.0.0" ') == "1.0.0"
    assert clean_version(None) == ""


def test_is_uncertain():
    assert is_uncertain("*")
    assert is_uncertain("")
    assert not is_uncertain("<1.0")


# ==========================================================================
#  방향 2 — 범위식 → 버전 포함 여부 (의미 검증)
# ==========================================================================
MEMBERSHIP_CASES = [
    # (범위식, 포함되는 버전들, 제외되는 버전들)
    ("<1.4.2", ["0.1", "1.0.0", "1.4.1"], ["1.4.2", "1.5.0", "2.0.0"]),
    (">=1.0.0,<1.4.2", ["1.0.0", "1.2.9", "1.4.1"], ["0.9.9", "1.4.2", "2.0.0"]),
    (">=2.0.0,<2.3.1|>=3.0.0,<3.0.4",
     ["2.0.0", "2.3.0", "3.0.0", "3.0.3"], ["1.9.9", "2.3.1", "3.0.4", "4.0.0"]),
    ("==1.2.3", ["1.2.3"], ["1.2.2", "1.2.4"]),
    ("*", ["0.0.1", "1.0.0", "99.99.99"], []),
    (">=1.0.0,<=1.4.1", ["1.0.0", "1.4.1"], ["0.9", "1.4.2"]),
    (">1.0.0", ["1.0.1", "2.0.0"], ["1.0.0", "0.9.9"]),
    ("<=0.9.9", ["0.1.0", "0.9.9"], ["1.0.0"]),
    ("==1.0.0|==1.0.1", ["1.0.0", "1.0.1"], ["1.0.2"]),
    (">=2.1.0", ["2.1.0", "10.0.0"], ["2.0.9"]),
]


@pytest.mark.parametrize("expr, inside, outside", MEMBERSHIP_CASES)
def test_membership(expr, inside, outside):
    for version in inside:
        assert matches(expr, version), f"{version} 은 {expr} 에 포함되어야 한다"
    for version in outside:
        assert not matches(expr, version), f"{version} 은 {expr} 에서 빠져야 한다"


ROUNDTRIP_CASES = [
    # (설명, 소스 원자료를 변환한 범위식, 취약한 버전, 안전한 버전)
    ("OSV 조치 전/후",
     join_ranges(osv_events_to_exprs([{"introduced": "0"}, {"fixed": "2.6.0"}])),
     "2.5.9", "2.6.0"),
    ("OSV 두 갈래",
     join_ranges(osv_events_to_exprs(
         [{"introduced": "2.0.0"}, {"fixed": "2.3.1"},
          {"introduced": "3.0.0"}, {"fixed": "3.0.4"}])),
     "3.0.3", "2.3.1"),
    ("NVD 경계",
     nvd_cpe_match_to_expr({"versionStartIncluding": "1.0",
                            "versionEndExcluding": "1.4.2"}),
     "1.4.1", "1.4.2"),
    ("GHSA 문자열",
     ghsa_range_to_expr(">= 1.0.0, < 1.4.2"),
     "1.0.0", "0.9.9"),
    ("GHSA 단일 등호",
     ghsa_range_to_expr("= 1.2.3"), "1.2.3", "1.2.4"),
    ("OSV last_affected",
     join_ranges(osv_events_to_exprs([{"introduced": "1.0.0"},
                                      {"last_affected": "1.4.1"}])),
     "1.4.1", "1.4.2"),
]


@pytest.mark.parametrize("desc, expr, vulnerable, safe", ROUNDTRIP_CASES)
def test_roundtrip(desc, expr, vulnerable, safe):
    assert matches(expr, vulnerable), f"{desc}: {vulnerable} 는 취약해야 한다 ({expr})"
    assert not matches(expr, safe), f"{desc}: {safe} 는 안전해야 한다 ({expr})"
