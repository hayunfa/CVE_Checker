"""GitHub Security Advisory (GHSA) 수집 — GraphQL `securityVulnerabilities`.

`vulnerableVersionRange` 와 `firstPatchedVersion` 을 그대로 쓸 수 있어
OSV 다음으로 버전 정보가 정확하다.

인증: `GITHUB_TOKEN` (GitHub Actions 가 자동 주입. 로컬은 public_repo 권한 PAT).
토큰이 없으면 이 소스만 건너뛴다(다른 소스는 정상 동작).

단독 실행:  python -m src.aicve.sources.ghsa --groups ui --lookback 30
"""
from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional, Tuple

from ..logutil import get_logger
from ..normalize import (
    Finding,
    clean_version,
    cvss31_base_score,
    ghsa_range_to_expr,
    join_ranges,
    severity_from_score,
    severity_from_text,
    to_yyyymmdd,
)
from .base import SourceError, SourceResult, build_client, now_stamp

log = get_logger("ghsa")

GRAPHQL_URL = "https://api.github.com/graphql"

# watchlist 좌표 키 → GHSA ecosystem enum
ECOSYSTEM_MAP = {"pypi": "PIP", "npm": "NPM", "go": "GO"}

QUERY = """
query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!, $size: Int!, $after: String) {
  securityVulnerabilities(ecosystem: $ecosystem, package: $package,
                          first: $size, after: $after) {
    pageInfo { hasNextPage endCursor }
    nodes {
      package { name ecosystem }
      vulnerableVersionRange
      firstPatchedVersion { identifier }
      severity
      updatedAt
      advisory {
        ghsaId
        summary
        description
        publishedAt
        updatedAt
        withdrawnAt
        permalink
        identifiers { type value }
        cvss { score vectorString }
      }
    }
  }
}
"""


def _token() -> str:
    return (os.environ.get("GITHUB_TOKEN")
            or os.environ.get("GH_TOKEN") or "").strip()


def _cve_id_of(advisory: Dict[str, Any]) -> Optional[str]:
    for identifier in advisory.get("identifiers") or []:
        if str(identifier.get("type", "")).upper() == "CVE":
            value = str(identifier.get("value", "")).upper()
            if value.startswith("CVE-"):
                return value
    return None


def _severity_of(node: Dict[str, Any],
                 advisory: Dict[str, Any]) -> Tuple[Optional[float], str, str]:
    cvss = advisory.get("cvss") or {}
    vector = str(cvss.get("vectorString") or "")
    score = cvss.get("score")
    if not score:                       # GHSA 는 점수 0 으로 비어 있는 경우가 있다
        score = cvss31_base_score(vector)
    if score:
        return float(score), vector, severity_from_score(float(score))
    return None, vector, severity_from_text(node.get("severity"))


def collect(scope) -> SourceResult:
    result = SourceResult(name="GHSA")
    started = time.time()

    token = _token()
    if not token:
        result.ok = False
        result.error = "GITHUB_TOKEN 이 없어 GHSA 조회를 건너뜁니다."
        log.warning(result.error)
        return result

    client = build_client(scope, {"Authorization": f"bearer {token}"})
    page_size = int(scope.collect.get("ghsa_page_size", 100))
    range_max_len = int(scope.output.get("range_max_len", 500))
    summary_max_len = int(scope.output.get("summary_max_len", 1000))
    start_date, end_date = scope.date_range()
    start_key, end_key = start_date.strftime("%Y%m%d"), end_date.strftime("%Y%m%d")
    stamp = now_stamp()

    # (CVE, S/W) 별로 여러 vulnerableVersionRange 가 나올 수 있어 모았다가 합친다
    buckets: Dict[Tuple[str, str], Dict[str, Any]] = {}

    try:
        for target in scope.targets:
            for key, ecosystem in ECOSYSTEM_MAP.items():
                package = target.get(key)
                if not package:
                    continue

                cursor: Optional[str] = None
                while True:
                    payload = {"query": QUERY, "variables": {
                        "ecosystem": ecosystem, "package": str(package),
                        "size": page_size, "after": cursor}}
                    data = client.post_json(GRAPHQL_URL, payload)

                    if data.get("errors"):
                        message = "; ".join(
                            str(e.get("message")) for e in data["errors"])
                        raise SourceError(f"GraphQL 오류: {message}")

                    block = ((data.get("data") or {}).get("securityVulnerabilities") or {})
                    for node in block.get("nodes") or []:
                        advisory = node.get("advisory") or {}
                        if advisory.get("withdrawnAt"):
                            continue
                        modified = to_yyyymmdd(advisory.get("updatedAt")
                                               or node.get("updatedAt"))
                        if modified and not (start_key <= modified <= end_key):
                            continue
                        cve_id = _cve_id_of(advisory)
                        if not cve_id:
                            continue

                        canonical = target["canonical_name"]
                        bucket = buckets.setdefault((cve_id, canonical), {
                            "target": target, "ranges": [], "fixed": "",
                            "node": node, "advisory": advisory, "modified": modified,
                        })
                        bucket["ranges"].append(
                            ghsa_range_to_expr(node.get("vulnerableVersionRange")))
                        patched = (node.get("firstPatchedVersion") or {}).get("identifier")
                        if patched and not bucket["fixed"]:
                            bucket["fixed"] = clean_version(patched)

                    page = block.get("pageInfo") or {}
                    if page.get("hasNextPage"):
                        cursor = page.get("endCursor")
                        continue
                    break

        for (cve_id, canonical), bucket in buckets.items():
            node, advisory = bucket["node"], bucket["advisory"]
            score, vector, severity = _severity_of(node, advisory)
            summary = (advisory.get("summary") or "")
            description = (advisory.get("description") or "")
            body = f"{summary} {description}".strip() if summary else description
            result.findings.append(Finding(
                cve_id=cve_id,
                sw_name=canonical,
                source="GHSA",
                vendor=bucket["target"].get("vendor", "") or "",
                ecosystem=bucket["target"].get("ecosystem", "other"),
                affected_range=join_ranges(bucket["ranges"], range_max_len),
                fixed_version=bucket["fixed"],
                severity=severity,
                cvss_score=score,
                cvss_vector=vector,
                published_date=to_yyyymmdd(advisory.get("publishedAt")),
                modified_date=bucket["modified"],
                summary=body[:summary_max_len * 2],
                reference_url=advisory.get("permalink") or "",
                collected_at=stamp,
            ))

        log.info("GHSA 수집 완료: %d건", len(result.findings))

    except SourceError as exc:
        result.ok = False
        result.error = str(exc)
        log.error("GHSA 수집 실패 — 이 소스만 건너뜁니다: %s", exc)
    except Exception as exc:
        result.ok = False
        result.error = f"{type(exc).__name__}: {exc}"
        log.exception("GHSA 수집 중 예상치 못한 오류")
    finally:
        result.requests_made = client.request_count
        result.elapsed_sec = time.time() - started
        client.close()
    return result


if __name__ == "__main__":
    from .base import print_findings, standalone_scope

    scope_obj, limit = standalone_scope("GitHub Advisory 단독 수집")
    print(scope_obj.desc)
    print_findings(collect(scope_obj), limit)
