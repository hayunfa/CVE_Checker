"""수집 소스 공통 기반.

- HttpClient : requests.Session + 재시도(429/5xx, exponential backoff) + timeout
- SourceResult : 소스 1곳의 수집 결과. 실패해도 예외를 위로 던지지 않고
                 ok=False 로 표시해 '부분 실패 허용'을 구현한다.
"""
from __future__ import annotations

import argparse
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests

from ..logutil import get_logger
from ..normalize import Finding

log = get_logger("source")

DEFAULT_TIMEOUT = 30
DEFAULT_RETRIES = 5
DEFAULT_BACKOFF = 1.5
DEFAULT_UA = "ai-cve-watch/1.0"
RETRY_STATUS = {408, 425, 429, 500, 502, 503, 504}


class SourceError(RuntimeError):
    """소스 수집 실패. collect() 안에서 잡아 SourceResult.ok=False 로 바꾼다."""


@dataclass
class SourceResult:
    """소스 1곳의 수집 결과."""

    name: str                                   # NVD / OSV / GHSA / KEV
    ok: bool = True
    findings: List[Finding] = field(default_factory=list)
    kev_ids: set = field(default_factory=set)   # KEV 전용
    error: str = ""
    requests_made: int = 0
    elapsed_sec: float = 0.0

    @property
    def count(self) -> int:
        return len(self.kev_ids) if self.name == "KEV" else len(self.findings)

    def summary(self) -> str:
        if not self.ok:
            return f"{self.name}: 실패 ({self.error})"
        return f"{self.name}: {self.count}건 ({self.requests_made}요청, {self.elapsed_sec:.1f}초)"


class HttpClient:
    """재시도가 붙은 HTTP 클라이언트."""

    def __init__(self, config: Optional[Dict[str, Any]] = None,
                 headers: Optional[Dict[str, str]] = None):
        config = config or {}
        self.timeout = int(config.get("timeout", DEFAULT_TIMEOUT))
        self.max_retries = int(config.get("max_retries", DEFAULT_RETRIES))
        self.backoff_base = float(config.get("backoff_base", DEFAULT_BACKOFF))
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": str(config.get("user_agent", DEFAULT_UA)),
            "Accept": "application/json",
        })
        if headers:
            self.session.headers.update(headers)
        self.request_count = 0

    # ------------------------------------------------------------------
    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """429/5xx 는 지수 백오프로 재시도. 끝까지 실패하면 SourceError."""
        kwargs.setdefault("timeout", self.timeout)
        last_error = ""
        for attempt in range(1, self.max_retries + 1):
            try:
                self.request_count += 1
                response = self.session.request(method, url, **kwargs)
                if response.status_code in RETRY_STATUS:
                    wait = self._retry_after(response, attempt)
                    last_error = f"HTTP {response.status_code}"
                    log.warning("%s %s → %s, %.1f초 후 재시도 (%d/%d)",
                                method, url, last_error, wait, attempt, self.max_retries)
                    time.sleep(wait)
                    continue
                response.raise_for_status()
                return response
            except requests.HTTPError as exc:
                raise SourceError(f"{method} {url} 실패: HTTP "
                                  f"{exc.response.status_code if exc.response else '?'}") from exc
            except requests.RequestException as exc:
                last_error = type(exc).__name__
                wait = self.backoff_base ** attempt
                log.warning("%s %s → %s, %.1f초 후 재시도 (%d/%d)",
                            method, url, last_error, wait, attempt, self.max_retries)
                if attempt < self.max_retries:
                    time.sleep(wait)
        raise SourceError(f"{method} {url} 재시도 {self.max_retries}회 모두 실패: {last_error}")

    def _retry_after(self, response: requests.Response, attempt: int) -> float:
        header = response.headers.get("Retry-After")
        if header:
            try:
                return min(float(header), 60.0)
            except ValueError:
                pass
        return float(self.backoff_base ** attempt)

    def get_json(self, url: str, params: Optional[Dict[str, Any]] = None,
                 **kwargs) -> Any:
        return self._json(self.request("GET", url, params=params, **kwargs))

    def post_json(self, url: str, payload: Any, **kwargs) -> Any:
        return self._json(self.request("POST", url, json=payload, **kwargs))

    @staticmethod
    def _json(response: requests.Response) -> Any:
        try:
            return response.json()
        except ValueError as exc:
            raise SourceError(f"JSON 파싱 실패: {response.url}") from exc

    def close(self) -> None:
        self.session.close()


def now_stamp() -> str:
    """COLLECTED_AT 용 YYYYMMDDHHmmss."""
    return datetime.now().strftime("%Y%m%d%H%M%S")


def build_client(scope, headers: Optional[Dict[str, str]] = None) -> HttpClient:
    return HttpClient(scope.collect, headers)


# --------------------------------------------------------------------------
#  단독 실행 지원 (python -m src.aicve.sources.osv --groups serving)
# --------------------------------------------------------------------------
def standalone_scope(description: str):
    """각 소스 모듈을 단독으로 돌려볼 때 쓰는 Scope 생성기."""
    from ..logutil import new_run_id, setup_logging
    from ..scope import resolve_scope

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--preset", default=None)
    parser.add_argument("--lookback", dest="lookback_days", default=None)
    parser.add_argument("--from", dest="date_from", default=None)
    parser.add_argument("--to", dest="date_to", default=None)
    parser.add_argument("--groups", default=None)
    parser.add_argument("--sw-names", dest="sw_names", default=None)
    parser.add_argument("--only-in-use", dest="only_in_use",
                        action="store_true", default=None)
    parser.add_argument("--min-severity", dest="min_severity", default=None)
    parser.add_argument("--limit", type=int, default=10,
                        help="화면에 출력할 건수")
    args = parser.parse_args()

    setup_logging(new_run_id())
    cli = {k: v for k, v in vars(args).items() if k != "limit"}
    return resolve_scope(cli=cli), args.limit


def print_findings(result: SourceResult, limit: int = 10) -> None:
    """단독 실행 시 결과를 보기 좋게 출력."""
    print()
    print("=" * 100)
    print(result.summary())
    print("=" * 100)
    for finding in result.findings[:limit]:
        print(f"{finding.cve_id:18} {finding.sw_name:20} {finding.severity:9} "
              f"{str(finding.cvss_score or '-'):5} {finding.affected_range[:40]:42} "
              f"fixed={finding.fixed_version or '-'}")
    if len(result.findings) > limit:
        print(f"... 외 {len(result.findings) - limit}건")
