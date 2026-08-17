"""SUMMARY 한국어 번역.

영문 원문은 그대로 두고(DB `cve.summary_en`), 엑셀·메일·페이지에 실리는
`SUMMARY` 만 한국어로 바꾼다. 엑셀 헤더 16개 규격은 건드리지 않는다.

  - 한 번 번역한 문장은 DB(`translation` 표)에 캐시해 다시 번역하지 않는다.
    매일 같은 CVE 를 다시 번역하면 무료 한도에 걸리기 때문이다.
  - 번역이 실패해도 실행을 멈추지 않는다. 실패한 건은 영문 원문을 그대로 쓴다.
  - 제공자
      google : 키 불필요(기본). 무료 엔드포인트라 대량 요청 시 제한될 수 있다.
      papago : NAVER_CLIENT_ID / NAVER_CLIENT_SECRET (네이버 개발자센터 무료 등록)
      deepl  : DEEPL_API_KEY (무료 플랜 월 50만자)
      none   : 번역하지 않음
"""
from __future__ import annotations

import hashlib
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

import requests

from .logutil import get_logger
from .normalize import RANGE_UNCERTAIN_PREFIX, Finding, clean_summary

log = get_logger("translate")

GOOGLE_URL = "https://translate.googleapis.com/translate_a/single"
PAPAGO_URL = "https://naveropenapi.apigw.ntruss.com/nmt/v1/translation"
DEEPL_FREE_URL = "https://api-free.deepl.com/v2/translate"
DEEPL_PRO_URL = "https://api.deepl.com/v2/translate"

# 번역하면 뜻이 흐려지는 토큰은 잠시 빼놨다가 되돌린다
_KEEP_PATTERNS = [
    re.compile(r"CVE-\d{4}-\d{4,7}", re.I),
    re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.I),
    re.compile(r"https?://\S+"),
]


@dataclass
class TranslateConfig:
    enabled: bool = False
    provider: str = "google"
    target_lang: str = "ko"
    mode: str = "replace"          # replace = 한국어만 / append = 한국어 + 영문 원문
    sleep: float = 0.3             # 요청 간 대기(초)
    max_retries: int = 3
    timeout: int = 20
    max_chars: int = 1000          # 이보다 긴 원문은 잘라서 번역

    @classmethod
    def from_output(cls, output: Dict[str, Any]) -> "TranslateConfig":
        """settings.yml 의 output.translate 를 읽는다. bool 과 블록 둘 다 허용."""
        raw = (output or {}).get("translate", False)
        if isinstance(raw, bool):
            return cls(enabled=raw)
        if not isinstance(raw, dict):
            return cls(enabled=False)
        config = cls(
            enabled=bool(raw.get("enabled", False)),
            provider=str(raw.get("provider", "google")).lower().strip(),
            target_lang=str(raw.get("target_lang", "ko")).lower().strip(),
            mode=str(raw.get("mode", "replace")).lower().strip(),
            sleep=float(raw.get("sleep", 0.3)),
            max_retries=int(raw.get("max_retries", 3)),
            timeout=int(raw.get("timeout", 20)),
            max_chars=int(raw.get("max_chars", 1000)),
        )
        if config.mode not in ("replace", "append"):
            log.warning("translate.mode 값이 잘못돼 replace 로 처리합니다: %s", config.mode)
            config.mode = "replace"
        return config


@dataclass
class TranslateStat:
    translated: int = 0
    cached: int = 0
    failed: int = 0
    skipped: int = 0
    provider: str = ""
    errors: List[str] = field(default_factory=list)

    def summary(self) -> str:
        return (f"번역 {self.translated}건 / 캐시재사용 {self.cached}건 / "
                f"실패 {self.failed}건 / 대상외 {self.skipped}건 ({self.provider})")


def text_key(text: str, lang: str) -> str:
    return hashlib.sha256(f"{lang}\x00{text}".encode("utf-8")).hexdigest()


# ==========================================================================
#  제공자별 호출
# ==========================================================================
class TranslationError(RuntimeError):
    pass


def _mask_keepers(text: str) -> tuple[str, List[str]]:
    """CVE 번호·URL 을 자리표시자로 바꿔 번역기가 건드리지 못하게 한다."""
    keepers: List[str] = []

    def replace(match: re.Match) -> str:
        keepers.append(match.group(0))
        return f"[[{len(keepers) - 1}]]"

    for pattern in _KEEP_PATTERNS:
        text = pattern.sub(replace, text)
    return text, keepers


def _restore_keepers(text: str, keepers: Sequence[str]) -> str:
    for index, original in enumerate(keepers):
        # 번역기가 공백을 넣는 경우까지 감안한다
        text = re.sub(rf"\[\s*\[\s*{index}\s*\]\s*\]", original.replace("\\", r"\\"), text)
    return text


def _google(session: requests.Session, text: str, lang: str, timeout: int) -> str:
    response = session.get(
        GOOGLE_URL,
        params={"client": "gtx", "sl": "auto", "tl": lang, "dt": "t", "q": text},
        headers={"User-Agent": "Mozilla/5.0"},
        timeout=timeout)
    if response.status_code != 200:
        raise TranslationError(f"HTTP {response.status_code}")
    try:
        payload = response.json()
        return "".join(segment[0] for segment in payload[0] if segment and segment[0])
    except (ValueError, IndexError, TypeError) as exc:
        raise TranslationError(f"응답 해석 실패: {exc}") from exc


def _papago(session: requests.Session, text: str, lang: str, timeout: int) -> str:
    client_id = os.environ.get("NAVER_CLIENT_ID", "").strip()
    client_secret = os.environ.get("NAVER_CLIENT_SECRET", "").strip()
    if not client_id or not client_secret:
        raise TranslationError("NAVER_CLIENT_ID / NAVER_CLIENT_SECRET 이 없습니다.")
    response = session.post(
        PAPAGO_URL,
        headers={"X-NCP-APIGW-API-KEY-ID": client_id,
                 "X-NCP-APIGW-API-KEY": client_secret},
        data={"source": "en", "target": lang, "text": text},
        timeout=timeout)
    if response.status_code != 200:
        raise TranslationError(f"HTTP {response.status_code}")
    return response.json()["message"]["result"]["translatedText"]


def _deepl(session: requests.Session, text: str, lang: str, timeout: int) -> str:
    api_key = os.environ.get("DEEPL_API_KEY", "").strip()
    if not api_key:
        raise TranslationError("DEEPL_API_KEY 가 없습니다.")
    url = DEEPL_PRO_URL if not api_key.endswith(":fx") else DEEPL_FREE_URL
    response = session.post(
        url,
        headers={"Authorization": f"DeepL-Auth-Key {api_key}"},
        data={"text": text, "target_lang": lang.upper()},
        timeout=timeout)
    if response.status_code != 200:
        raise TranslationError(f"HTTP {response.status_code}")
    return response.json()["translations"][0]["text"]


PROVIDERS = {"google": _google, "papago": _papago, "deepl": _deepl}


# ==========================================================================
#  번역기
# ==========================================================================
class Translator:
    """DB 캐시를 앞에 둔 번역기. 실패해도 예외를 위로 던지지 않는다."""

    def __init__(self, config: TranslateConfig, store=None):
        self.config = config
        self.store = store
        self.session = requests.Session()
        self.stat = TranslateStat(provider=config.provider)
        self._memory: Dict[str, str] = {}     # 같은 실행 안에서의 중복 방지

    # ------------------------------------------------------------------
    def translate_text(self, text: str) -> Optional[str]:
        """한 문장 번역. 실패하면 None."""
        source = (text or "").strip()
        if not source:
            return None

        if len(source) > self.config.max_chars:
            source = source[: self.config.max_chars]

        key = text_key(source, self.config.target_lang)
        if key in self._memory:
            self.stat.cached += 1
            return self._memory[key]

        if self.store is not None:
            cached = self.store.get_translation(key)
            if cached:
                self._memory[key] = cached
                self.stat.cached += 1
                return cached

        handler = PROVIDERS.get(self.config.provider)
        if handler is None:
            self.stat.failed += 1
            self._note_error(f"알 수 없는 번역 제공자: {self.config.provider}")
            return None

        masked, keepers = _mask_keepers(source)
        for attempt in range(1, self.config.max_retries + 1):
            try:
                result = handler(self.session, masked, self.config.target_lang,
                                 self.config.timeout)
                result = _restore_keepers(result, keepers).strip()
                if not result:
                    raise TranslationError("빈 응답")
                self._memory[key] = result
                if self.store is not None:
                    self.store.save_translation(key, self.config.target_lang, source,
                                                result, self.config.provider)
                self.stat.translated += 1
                if self.config.sleep:
                    time.sleep(self.config.sleep)
                return result
            except Exception as exc:
                message = f"{type(exc).__name__}: {exc}"
                if attempt < self.config.max_retries:
                    wait = min(2 ** attempt, 10)
                    log.warning("번역 실패, %.0f초 후 재시도 (%d/%d): %s",
                                wait, attempt, self.config.max_retries, message)
                    time.sleep(wait)
                else:
                    self.stat.failed += 1
                    self._note_error(message)
        return None

    def _note_error(self, message: str) -> None:
        if message not in self.stat.errors:
            self.stat.errors.append(message)
        if len(self.stat.errors) == 1:
            log.error("번역 실패 — 해당 건은 영문 원문을 그대로 씁니다: %s", message)

    # ------------------------------------------------------------------
    def apply(self, findings: Sequence[Finding],
              summary_max_len: int = 1000) -> TranslateStat:
        """findings 의 SUMMARY 를 한국어로 바꾼다 (원문은 summary_en 에 보존)."""
        if not self.config.enabled:
            self.stat.skipped = len(findings)
            return self.stat

        log.info("SUMMARY 번역 시작: %d건 (제공자 %s, 모드 %s)",
                 len(findings), self.config.provider, self.config.mode)

        for finding in findings:
            original = finding.summary or ""
            if not original.strip():
                self.stat.skipped += 1
                continue

            # 범위 불명확 접두사는 번역기에 넘기지 않고 결과 앞에 다시 붙인다
            has_prefix = original.startswith(RANGE_UNCERTAIN_PREFIX)
            body = original[len(RANGE_UNCERTAIN_PREFIX):] if has_prefix else original

            # 영문 원문은 접두사까지 포함한 형태로 보존한다(변경 감지 해시의 기준).
            # 이미 채워져 있으면(merge 단계에서 설정됨) 건드리지 않는다.
            if not finding.summary_en:
                finding.summary_en = original
            translated = self.translate_text(body)
            if not translated:
                continue                          # 실패 → 영문 그대로 둔다

            if self.config.mode == "append":
                merged = f"{translated} / [원문] {body}"
            else:
                merged = translated
            prefix = RANGE_UNCERTAIN_PREFIX if has_prefix else ""
            finding.summary = clean_summary(merged, summary_max_len, prefix)

        log.info(self.stat.summary())
        if self.stat.failed:
            log.warning("번역 실패 %d건은 영문 원문으로 기록됐습니다.", self.stat.failed)
        return self.stat

    def close(self) -> None:
        self.session.close()


def translate_findings(findings: Sequence[Finding], scope, store=None) -> TranslateStat:
    """main.py 에서 부르는 진입점."""
    config = TranslateConfig.from_output(scope.output)
    translator = Translator(config, store)
    try:
        return translator.apply(
            findings, int(scope.output.get("summary_max_len", 1000)))
    finally:
        translator.close()


def backfill(store, scope, limit: Optional[int] = None,
             retranslate: bool = False) -> TranslateStat:
    """DB 에 이미 쌓인 건을 한 번에 번역한다.

    수집 단계의 번역은 '그 실행에서 수집된 건' 에만 적용된다.
    번역 기능을 켜기 전에 쌓인 건이나, 일시적으로 번역이 실패했던 건은
    매일 실행이 최근 며칠치만 다시 훑기 때문에 영영 영문으로 남는다.
    이 함수가 그 구멍을 메운다.

    retranslate=False 면 아직 번역 안 된 건(summary_en 이 빈 건)만 처리한다.
    """
    from .store import content_hash, rows_to_findings

    config = TranslateConfig.from_output(scope.output)
    if not config.enabled:
        log.warning("settings.yml 의 output.translate.enabled 가 꺼져 있습니다.")
        return TranslateStat(provider=config.provider)

    rows = store.fetch_all_cves()
    targets = [r for r in rows
               if retranslate or not (r.get("summary_en") or "").strip()]
    if limit:
        targets = targets[:limit]

    log.info("번역 대상 %d건 (전체 %d건 중)", len(targets), len(rows))
    if not targets:
        log.info("이미 모두 번역돼 있습니다.")
        return TranslateStat(provider=config.provider)

    findings = rows_to_findings(targets)
    if retranslate:
        for finding in findings:              # 다시 번역하려면 원문을 되살린다
            if finding.summary_en:
                finding.summary = finding.summary_en

    translator = Translator(config, store)
    try:
        stat = translator.apply(
            findings, int(scope.output.get("summary_max_len", 1000)))
    finally:
        translator.close()

    # 값만 갱신한다. 회차 정보(first/last_seen_run)는 그대로 둔다 —
    # 재수집이 아니라 표기 보정이므로 이력이 바뀌면 안 된다.
    original = {(r["cve_id"], r["sw_name"]): r for r in targets}
    for finding in findings:
        row = original[(finding.cve_id, finding.sw_name)]
        store.conn.execute(
            "UPDATE cve SET summary=?, summary_en=?, content_hash=? "
            "WHERE cve_id=? AND sw_name=?",
            (finding.summary, finding.summary_en, content_hash(finding),
             finding.cve_id, finding.sw_name))
    store.conn.commit()
    log.info("DB 반영 완료: %d건", len(findings))
    return stat


def _main() -> int:
    """python -m src.aicve.translate  [--backfill] [문장]"""
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m src.aicve.translate",
        description="SUMMARY 번역 도구 (한 문장 확인 / DB 일괄 번역)")
    parser.add_argument("text", nargs="*", help="번역해 볼 영문 문장")
    parser.add_argument("--backfill", action="store_true",
                        help="DB 에 이미 쌓인 건 중 아직 번역 안 된 것을 번역")
    parser.add_argument("--retranslate", action="store_true",
                        help="이미 번역된 건도 다시 번역 (제공자를 바꿨을 때)")
    parser.add_argument("--limit", type=int, default=None, help="처리 건수 제한")
    parser.add_argument("--db", default="data/cve.db")
    parser.add_argument("--config", default="config/settings.yml")
    parser.add_argument("--watchlist", default="config/watchlist.yml")
    args = parser.parse_args()

    if args.backfill or args.retranslate:
        from .logutil import new_run_id, setup_logging
        from .scope import resolve_scope
        from .store import SqliteStore

        setup_logging(new_run_id())
        scope = resolve_scope(cli={}, settings_path=args.config,
                              watchlist_path=args.watchlist)
        store = SqliteStore(args.db)
        try:
            stat = backfill(store, scope, args.limit, args.retranslate)
            print(stat.summary())
        finally:
            store.close()
        return 0

    sample = " ".join(args.text) or (
        "A flaw was found in vLLM (CVE-2025-32444). A malicious client can send a "
        "crafted prompt causing unbounded memory allocation, resulting in denial of "
        "service. See https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz for details.")
    config = TranslateConfig(enabled=True,
                             provider=os.environ.get("TRANSLATE_PROVIDER", "google"))
    translator = Translator(config)
    print(f"[원문] {sample}\n")
    print(f"[번역] {translator.translate_text(sample)}\n")
    print(translator.stat.summary())
    translator.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
