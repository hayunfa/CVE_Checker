"""로그 마스킹 검증.

Actions 로그는 공개될 수 있으므로 비밀번호·토큰·수신자 주소가 절대 남으면 안 된다.
"""
from __future__ import annotations

import logging

import pytest

from src.aicve.logutil import mask, new_run_id, setup_logging

SECRETS = [
    "abcdefghijklmnop",                          # Gmail 앱 비밀번호
    "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz123456",      # GitHub 토큰
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0",      # JWT
    "hunter2",
]


@pytest.mark.parametrize("text, leaked", [
    ("SMTP_PASS=abcdefghijklmnop 로 로그인", "abcdefghijklmnop"),
    ("password: hunter2 입니다", "hunter2"),
    ('{"api_key": "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz123456"}',
     "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz123456"),
    ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0",
     "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0"),
    ("Authorization: bearer ghp_AbCdEfGhIjKlMnOpQrStUvWxYz123456",
     "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz123456"),
    ("token=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz123456",
     "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz123456"),
    ("secret='hunter2'", "hunter2"),
])
def test_secret_never_survives_masking(text, leaked):
    assert leaked not in mask(text), f"비밀값이 로그에 남았다: {text}"


def test_email_partially_masked():
    assert mask("수신자 hong.gildong@corp.co.kr") == "수신자 ho***@corp.co.kr"
    assert "hong.gildong" not in mask("hong.gildong@corp.co.kr")


def test_env_secret_value_replaced(monkeypatch):
    monkeypatch.setenv("SMTP_PASS", "sUperSecret123")
    assert "sUperSecret123" not in mask("로그인 실패: sUperSecret123 거부됨")


def test_short_env_value_not_replaced(monkeypatch):
    """3자 이하 값까지 치환하면 멀쩡한 로그가 뭉개진다."""
    monkeypatch.setenv("SMTP_USER", "ab")
    assert mask("about") == "about"


def test_mask_handles_empty_and_none():
    assert mask("") == ""
    assert mask(None) is None


def test_normal_text_untouched():
    text = "OSV 수집 완료: 376건 (378요청, 109.2초)"
    assert mask(text) == text
    assert mask("CVE-2026-0001 PyTorch >=1.0.0,<1.4.2") == \
        "CVE-2026-0001 PyTorch >=1.0.0,<1.4.2"


def test_log_file_is_masked(tmp_path, monkeypatch):
    """실제 로그 파일에도 마스킹이 적용되는지."""
    monkeypatch.setenv("SMTP_PASS", "abcdefghijklmnop")
    run_id = new_run_id()
    log_path = setup_logging(run_id, tmp_path)
    logging.getLogger("test").info(
        "발송 시도 user@example.com / SMTP_PASS=abcdefghijklmnop")
    for handler in logging.getLogger().handlers:
        handler.flush()
    content = log_path.read_text(encoding="utf-8")
    assert "abcdefghijklmnop" not in content
    assert "user@example.com" not in content
    assert "us***@example.com" in content
    logging.getLogger().handlers.clear()
