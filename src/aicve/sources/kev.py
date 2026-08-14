"""CISA KEV (Known Exploited Vulnerabilities) 수집.

실제로 악용이 확인된 취약점 목록. 전량 다운로드해 CVE_ID 집합만 만든다.
이 집합에 들어 있으면 심각도와 무관하게 항상 엑셀·메일에 포함된다(KEV_YN='Y').

단독 실행:  python -m src.aicve.sources.kev
"""
from __future__ import annotations

import time
from typing import Dict, Set

from ..logutil import get_logger
from .base import SourceError, SourceResult, build_client

log = get_logger("kev")

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")


def collect(scope) -> SourceResult:
    """KEV 전량을 받아 CVE_ID 집합을 만든다."""
    result = SourceResult(name="KEV")
    started = time.time()
    client = build_client(scope)
    try:
        data = client.get_json(KEV_URL)
        vulnerabilities = data.get("vulnerabilities") or []
        result.kev_ids = {
            str(item.get("cveID", "")).strip().upper()
            for item in vulnerabilities
            if str(item.get("cveID", "")).strip()
        }
        log.info("KEV 등재 %d건 (카탈로그 %s)",
                 len(result.kev_ids), data.get("catalogVersion", "?"))
    except SourceError as exc:
        result.ok = False
        result.error = str(exc)
        log.error("KEV 수집 실패 — KEV_YN 은 전부 'N' 으로 기록된다: %s", exc)
    except Exception as exc:  # 예상 못한 오류도 전체 실행을 막지 않는다
        result.ok = False
        result.error = f"{type(exc).__name__}: {exc}"
        log.exception("KEV 수집 중 예상치 못한 오류")
    finally:
        result.requests_made = client.request_count
        result.elapsed_sec = time.time() - started
        client.close()
    return result


def kev_details(scope) -> Dict[str, Dict]:
    """CVE_ID → KEV 상세(악용 설명·조치기한). 메일 강조 표시에 쓸 수 있다."""
    client = build_client(scope)
    try:
        data = client.get_json(KEV_URL)
        return {str(item.get("cveID", "")).upper(): item
                for item in (data.get("vulnerabilities") or [])}
    except Exception as exc:
        log.warning("KEV 상세 조회 실패: %s", exc)
        return {}
    finally:
        client.close()


def fetch_kev_ids(scope) -> Set[str]:
    """다른 모듈에서 집합만 필요할 때."""
    return collect(scope).kev_ids


if __name__ == "__main__":
    from .base import standalone_scope

    scope_obj, limit = standalone_scope("CISA KEV 단독 수집")
    outcome = collect(scope_obj)
    print()
    print("=" * 60)
    print(outcome.summary())
    print("=" * 60)
    for cve in sorted(outcome.kev_ids)[:limit]:
        print(" ", cve)
    print(f"... 총 {len(outcome.kev_ids)}건")
