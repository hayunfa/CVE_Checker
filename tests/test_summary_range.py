"""SUMMARY 본문에서 버전 범위를 2차 추출하는 기능 검증.

핵심 원칙 3가지를 테스트로 못박는다.
  1. 요약문에 적힌 숫자만 쓴다 (브랜치 시작점 등을 지어내지 않는다)
  2. 애매하면 넓게 잡는다 (좁히다 진짜 취약점을 놓치지 않는다)
  3. 못 읽겠으면 '*' 를 그대로 둔다
"""
from __future__ import annotations

import pytest

from src.aicve.normalize import ALL_VERSIONS, RANGE_UNCERTAIN_PREFIX, Finding
from src.aicve.summary_range import (
    extract_fixed,
    extract_ranges,
    recover_from_summary,
    recover_missing_ranges,
)

# 테스트에서 범위식 의미를 되짚어 볼 때 쓰는 해석기 (내부망 파서와 같은 문법)
from .test_version_range import matches


# ==========================================================================
#  1. 요청받은 표현들 (■ 해달라는 것 2번 항목)
# ==========================================================================
REQUIRED = [
    ("From 0.19.0 until 0.26.0, the field accepts input.", ">=0.19.0,<0.26.0"),
    ("Affected from 1.0.0 to 2.0.0 in the parser.", ">=1.0.0,<2.0.0"),
    ("This affects versions before 2.6.0 of the library.", "<2.6.0"),
    ("The issue exists prior to 3.1.4 in all builds.", "<3.1.4"),
    ("Affects versions through 1.9.9 of the package.", "<=1.9.9"),
    ("This impacts up to 4.2.0 of the product.", "<=4.2.0"),
    ("Version 5.1.2 and earlier are affected.", "<=5.1.2"),
    ("Versions 1.0.0 - 1.4.2 contain the flaw.", ">=1.0.0,<=1.4.2"),
]


@pytest.mark.parametrize("text, expected", REQUIRED)
def test_required_patterns(text, expected):
    assert recover_from_summary(text)[0] == expected, text


FIXED_REQUIRED = [
    ("This issue is fixed in version 0.26.0.", "0.26.0"),
    ("The bug has been patched in 2.1.0 of the tool.", "2.1.0"),
    ("Users should upgrade to 3.0.1 immediately.", "3.0.1"),
    ("Resolved in 1.2.3 after review.", "1.2.3"),
]


@pytest.mark.parametrize("text, expected", FIXED_REQUIRED)
def test_required_fixed_patterns(text, expected):
    assert extract_fixed(text)[0] == expected, text


def test_and_later_is_a_fix_not_a_range():
    assert extract_fixed("Use 4.5.0 and later to stay safe.")[0] == "4.5.0"


# ==========================================================================
#  2. 증상으로 지목된 실제 2건
# ==========================================================================
VLLM_SUMMARY = (
    "vLLM is an inference and serving engine for large language models. "
    "From 0.19.0 until 0.26.0, the /v1/completions CompletionRequest.prompt field "
    "in vllm/entrypoints/openai/completion/protocol.py accepts an unbounded "
    "list[str] or list[list[int]], allowing an authenticated API client to exhaust "
    "CPU and memory with one request. This issue is fixed in version 0.26.0.")

GRPC_SUMMARY = (
    "A vulnerability has been found in SpaceX Starlink Router Gen 3 "
    "2025.11.14.mr64708.3. This affects the function get_status of the component "
    "gRPC Management Interface. The manipulation leads to improper access controls. "
    "The attack can only be initiated within the local network. The exploit has "
    "been disclosed to the public and may be used.")


def test_vllm_case_is_recovered():
    """CVE-2026-73559 — 요약문에 범위가 그대로 있는데 '*' 로 나가던 건."""
    expr, fixed = recover_from_summary(VLLM_SUMMARY)
    assert expr == ">=0.19.0,<0.26.0"
    assert fixed == "0.26.0"


def test_vllm_range_excludes_our_installed_version():
    """오탐의 실제 원인: 우리가 쓰는 0.6.6 이 영향 범위 밖으로 판정돼야 한다."""
    expr, _ = recover_from_summary(VLLM_SUMMARY)
    assert not matches(expr, "0.6.6"), "0.6.6 은 취약하지 않다"
    assert matches(expr, "0.19.0") and matches(expr, "0.25.9")
    assert not matches(expr, "0.26.0"), "조치된 버전은 빠져야 한다"


def test_grpc_case_stays_unknown():
    """CVE-2026-19918 — 제품 빌드 문자열뿐이라 '*' 로 남아야 한다."""
    assert recover_from_summary(GRPC_SUMMARY)[0] is None


def test_build_string_is_not_read_as_version():
    """'2025.11.14.mr64708.3' 에서 '2025.11.14' 만 떼어 읽으면 안 된다."""
    assert extract_ranges("Found in Starlink Router Gen 3 2025.11.14.mr64708.3.") == []


# ==========================================================================
#  3. 다중 범위 (파이프 구분) — CVE_20260815 실제 사례
# ==========================================================================
def test_multiple_before_clauses_become_or_range():
    """n8n: 'before A, 2.x before B, and 2.32.x before C' → 세 구간 OR"""
    text = ("n8n before 1.123.67, 2.x before 2.31.5, and 2.32.x before 2.32.1 "
            "contain a type confusion vulnerability.")
    assert recover_from_summary(text)[0] == "<1.123.67|<2.31.5|<2.32.1"


def test_branch_marker_not_read_as_version():
    """'2.32.x' 의 '2.32' 를 버전으로 읽으면 범위가 틀어진다."""
    text = "n8n before 2.31.5, and 2.32.x before 2.32.1 are affected."
    expr = recover_from_summary(text)[0]
    assert "<2.32|" not in expr and not expr.endswith("<2.32")
    assert expr == "<2.31.5|<2.32.1"


def test_comma_and_list_keeps_last_item():
    """'before A, B, and C' 에서 마지막 C 를 놓치면 범위가 좁아진다(취약점 누락)."""
    text = "n8n before 1.123.67, 2.31.5, and 2.32.1 contains SQL injection."
    expr = recover_from_summary(text)[0]
    assert matches(expr, "2.32.0"), "2.32.0 은 취약 범위에 들어야 한다"
    assert not matches(expr, "2.32.1")


def test_output_format_has_no_spaces():
    for text, _ in REQUIRED:
        expr = recover_from_summary(text)[0]
        assert " " not in expr, expr


# ==========================================================================
#  4. 애매하면 넓게 (원칙 2)
# ==========================================================================
def test_multiple_fix_versions_widen_upper_bound():
    """'until 4.5.10 and 4.6.2' — 브랜치 경계를 모르니 높은 쪽을 상한으로."""
    text = "From 3.3.0 until 4.5.10 and 4.6.2, JupyterLab allows settings import."
    expr = recover_from_summary(text)[0]
    assert expr == ">=3.3.0,<4.6.2"
    assert matches(expr, "4.6.1"), "4.6.1 을 놓치면 진짜 취약점을 놓친다"
    assert not matches(expr, "3.2.9"), "3.3.0 미만은 영향 없음"


def test_prior_to_multiple_versions():
    text = "Prior to 4.5.10 and 4.6.2, the image viewer allows XSS."
    assert recover_from_summary(text)[0] == "<4.6.2"


# ==========================================================================
#  5. 근거 없는 추정 금지 (원칙 1) / 못 읽으면 그대로 (원칙 3)
# ==========================================================================
NO_RANGE_TEXTS = [
    "A vulnerability allows remote code execution in the parser.",
    "The attacker can bypass authentication under certain conditions.",
    "An issue was discovered that leads to improper access controls.",
    "",
    "   ",
]


@pytest.mark.parametrize("text", NO_RANGE_TEXTS)
def test_no_version_means_no_guess(text):
    assert recover_from_summary(text)[0] is None


def test_bare_version_mention_is_not_a_range():
    """단순히 버전이 언급됐다고 범위로 만들면 안 된다."""
    assert recover_from_summary("Tested on 1.2.3 in our lab environment.")[0] is None


def test_other_product_version_ignored():
    assert extract_ranges("Requires python 3.11 to reproduce.") == []


def test_reversed_range_rejected():
    """'from 5.0 until 1.0' 처럼 말이 안 되는 구간은 버린다."""
    assert recover_from_summary("From 5.0.0 until 1.0.0 something happens.")[0] is None


# ==========================================================================
#  6. 파이프라인 연결 — '*' 인 건만 건드리고 나머지는 그대로
# ==========================================================================
def finding(**kwargs):
    base = dict(cve_id="CVE-2026-0001", sw_name="vLLM", source="OSV",
                affected_range=ALL_VERSIONS, fixed_version="",
                summary=RANGE_UNCERTAIN_PREFIX + VLLM_SUMMARY,
                summary_en=RANGE_UNCERTAIN_PREFIX + VLLM_SUMMARY)
    base.update(kwargs)
    return Finding(**base)


def test_recovers_and_strips_prefix():
    item = finding()
    assert recover_missing_ranges([item]) == 1
    assert item.affected_range == ">=0.19.0,<0.26.0"
    assert item.fixed_version == "0.26.0"
    assert not item.summary.startswith(RANGE_UNCERTAIN_PREFIX)
    assert not item.summary_en.startswith(RANGE_UNCERTAIN_PREFIX)


def test_existing_ranges_are_never_touched():
    """이미 범위가 채워진 건은 손대지 않는다 (회귀 방지)."""
    item = finding(affected_range=">=4.6.0,<4.6.2|<4.5.10", fixed_version="4.6.2",
                   summary="JupyterLab image viewer allows XSS from 1.0.0 until 2.0.0.")
    assert recover_missing_ranges([item]) == 0
    assert item.affected_range == ">=4.6.0,<4.6.2|<4.5.10"
    assert item.fixed_version == "4.6.2"


def test_failure_keeps_star_and_prefix():
    item = finding(summary=RANGE_UNCERTAIN_PREFIX + GRPC_SUMMARY,
                   summary_en=RANGE_UNCERTAIN_PREFIX + GRPC_SUMMARY)
    assert recover_missing_ranges([item]) == 0
    assert item.affected_range == ALL_VERSIONS
    assert item.summary.startswith(RANGE_UNCERTAIN_PREFIX)


def test_existing_fixed_version_not_overwritten():
    item = finding(fixed_version="9.9.9")
    recover_missing_ranges([item])
    assert item.fixed_version == "9.9.9"


def test_range_length_capped():
    text = " ".join(f"affected before {i}.0.0," for i in range(1, 80))
    item = finding(summary=text, summary_en=text)
    recover_missing_ranges([item], range_max_len=100)
    assert len(item.affected_range) <= 100
    assert not item.affected_range.endswith("|")
