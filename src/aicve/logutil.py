"""로깅 설정 + 비밀정보 마스킹.

콘솔과 logs/run_{run_id}.log 에 동시에 기록한다.
비밀번호·토큰·API 키·메일 주소는 기록 직전에 마스킹되므로
Actions 로그가 공개되어도 노출되지 않는다.
"""
from __future__ import annotations

import logging
import os
import re
import sys
from datetime import datetime
from pathlib import Path

LOG_FORMAT = "%(asctime)s [%(levelname)-7s] %(name)-14s %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# 값 자체를 지워야 하는 환경변수 (실제 값이 로그에 찍히면 통째로 치환)
SECRET_ENV_KEYS = (
    "SMTP_PASS",
    "SMTP_USER",
    "NVD_API_KEY",
    "GITHUB_TOKEN",
    "GH_TOKEN",
)

# 패턴 기반 마스킹 (문자열, 치환식)
# ★ 순서가 중요하다. 값이 여러 토큰으로 이루어진 형태(Bearer xxx)를 먼저 지워야 한다.
#   일반 key=value 규칙을 먼저 돌리면 'Authorization: Bearer xxx' 에서 'Bearer' 만
#   지워지고 정작 토큰 xxx 가 그대로 남는다.
_PATTERNS = [
    # GitHub 토큰
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}"), "***GH_TOKEN***"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), "***GH_TOKEN***"),
    # Bearer / Basic 인증 헤더 (값 전체)
    (re.compile(r"(?i)\b(Bearer|Basic|token)\s+[A-Za-z0-9._\-+/=]{8,}"), r"\1 ***MASKED***"),
    # key=value / "key": "value" 형태의 비밀값
    # 앞에 접두사가 붙은 이름(SMTP_PASS, X-Api-Key 등)도 잡도록 키 앞부분을 허용한다.
    # ('\b' 만 쓰면 밑줄도 단어문자라 SMTP_PASS 의 PASS 앞에서 경계가 성립하지 않는다)
    (re.compile(r'(?i)([A-Za-z0-9_.\-]*'
                r'(?:password|passwd|pwd|pass|token|api[_-]?key|secret|authorization))'
                r'(["\']?\s*[:=]\s*["\']?)([^\s"\',;)]+)'), r"\1\2***MASKED***"),
    # 메일 주소 → 앞 2글자만 남김  (hong@corp.com → ho***@corp.com)
    (re.compile(r"\b([A-Za-z0-9._%+-]{1,2})[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"),
     r"\1***@\2"),
]


def mask(text: str) -> str:
    """문자열에서 비밀정보를 지운다."""
    if not text:
        return text
    out = str(text)
    for key in SECRET_ENV_KEYS:
        val = os.environ.get(key)
        if val and len(val) >= 4:
            out = out.replace(val, "***MASKED***")
    for pattern, repl in _PATTERNS:
        out = pattern.sub(repl, out)
    return out


class MaskingFilter(logging.Filter):
    """레코드가 출력되기 직전에 메시지를 마스킹한다."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        try:
            record.msg = mask(record.getMessage())
            record.args = ()
        except Exception:  # 마스킹 실패가 로깅을 막아서는 안 된다
            pass
        return True


def new_run_id() -> str:
    """실행 ID (yyyyMMddHHmmss)."""
    return datetime.now().strftime("%Y%m%d%H%M%S")


def setup_logging(run_id: str, log_dir: str | Path = "logs",
                  level: int = logging.INFO) -> Path:
    """콘솔 + 파일 로깅을 구성하고 로그 파일 경로를 돌려준다."""
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"run_{run_id}.log"

    root = logging.getLogger()
    root.setLevel(level)
    for handler in list(root.handlers):  # 재실행 시 중복 방지
        root.removeHandler(handler)

    formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
    masker = MaskingFilter()

    # Windows 콘솔(cp949)에서 한글이 깨지지 않게 표준출력을 UTF-8 로 맞춘다
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.addFilter(masker)
    root.addHandler(file_handler)

    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(formatter)
    stream.addFilter(masker)
    root.addHandler(stream)

    # 외부 라이브러리 소음 억제
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    return log_path


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
