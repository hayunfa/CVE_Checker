"""SUMMARY 번역 검증 (네트워크 없이 가짜 제공자로 확인)."""
from __future__ import annotations

import pytest

from src.aicve import translate as tr
from src.aicve.normalize import RANGE_UNCERTAIN_PREFIX, Finding
from src.aicve.store import SqliteStore, content_hash


@pytest.fixture
def fake_provider(monkeypatch):
    """호출 횟수를 세는 가짜 번역기. 실제 API 를 부르지 않는다."""
    calls = []

    def handler(session, text, lang, timeout):
        calls.append(text)
        return f"[{lang}]{text}"

    monkeypatch.setitem(tr.PROVIDERS, "fake", handler)
    return calls


def config(**kwargs):
    base = dict(enabled=True, provider="fake", sleep=0, target_lang="ko")
    base.update(kwargs)
    return tr.TranslateConfig(**base)


def finding(summary="A flaw was found.", **kwargs):
    base = dict(cve_id="CVE-2026-0001", sw_name="PyTorch", source="OSV",
                summary=summary)
    base.update(kwargs)
    return Finding(**base)


# ==========================================================================
#  설정 읽기 (bool 과 블록 둘 다 지원)
# ==========================================================================
def test_config_from_bool():
    assert tr.TranslateConfig.from_output({"translate": False}).enabled is False
    enabled = tr.TranslateConfig.from_output({"translate": True})
    assert enabled.enabled is True and enabled.provider == "google"


def test_config_from_block():
    cfg = tr.TranslateConfig.from_output({"translate": {
        "enabled": True, "provider": "papago", "mode": "append", "sleep": 1.5}})
    assert (cfg.enabled, cfg.provider, cfg.mode, cfg.sleep) == (True, "papago", "append", 1.5)


def test_config_missing_or_invalid():
    assert tr.TranslateConfig.from_output({}).enabled is False
    assert tr.TranslateConfig.from_output({"translate": "yes"}).enabled is False
    assert tr.TranslateConfig.from_output(
        {"translate": {"enabled": True, "mode": "이상한값"}}).mode == "replace"


def test_real_settings_file_parses():
    from src.aicve.scope import load_settings
    cfg = tr.TranslateConfig.from_output(load_settings("config/settings.yml")["output"])
    assert cfg.provider in tr.PROVIDERS
    assert cfg.mode in ("replace", "append")


# ==========================================================================
#  번역 동작
# ==========================================================================
def test_disabled_leaves_summary_untouched(fake_provider):
    item = finding()
    tr.Translator(config(enabled=False)).apply([item])
    assert item.summary == "A flaw was found."
    assert fake_provider == []


def test_translates_and_keeps_english(fake_provider):
    item = finding()
    stat = tr.Translator(config()).apply([item])
    assert item.summary == "[ko]A flaw was found."
    assert item.summary_en == "A flaw was found."      # 원문 보존
    assert stat.translated == 1


def test_append_mode_keeps_both(fake_provider):
    item = finding()
    tr.Translator(config(mode="append")).apply([item])
    assert item.summary.startswith("[ko]A flaw was found.")
    assert "[원문] A flaw was found." in item.summary


def test_uncertain_prefix_preserved_and_not_translated(fake_provider):
    """'[버전범위 불명확]' 접두사는 번역기에 넘기지 않고 결과 앞에 다시 붙인다.

    단 summary_en 에는 접두사를 그대로 남긴다 — 변경 감지 해시의 기준이라
    접두사 유무가 어긋나면 번역과 무관한 건까지 '변경'으로 잡힌다.
    """
    item = finding(summary=RANGE_UNCERTAIN_PREFIX + "A flaw was found.")
    tr.Translator(config()).apply([item])
    assert item.summary.startswith(RANGE_UNCERTAIN_PREFIX)
    assert RANGE_UNCERTAIN_PREFIX not in fake_provider[0]     # 번역기에는 안 넘어감
    assert item.summary_en == RANGE_UNCERTAIN_PREFIX + "A flaw was found."


def test_merge_sets_matching_summary_en(fake_provider):
    """merge 단계의 summary 와 summary_en 은 접두사까지 같은 형태여야 한다."""
    from src.aicve.normalize import merge_findings

    raw = Finding(cve_id="CVE-2026-0001", sw_name="PyTorch", source="NVD",
                  affected_range="*", summary="A flaw was found.")
    merged = merge_findings([raw])[0]
    assert merged.summary.startswith(RANGE_UNCERTAIN_PREFIX)
    assert merged.summary_en == merged.summary


def test_translation_does_not_flag_uncertain_rows_as_changed(fake_provider):
    """범위 불명확 건도 번역 전후로 해시가 같아야 한다."""
    from src.aicve.normalize import merge_findings

    raw = Finding(cve_id="CVE-2026-0001", sw_name="PyTorch", source="NVD",
                  affected_range="*", summary="A flaw was found.")
    before = content_hash(merge_findings([raw])[0])

    after_item = merge_findings([raw])[0]
    tr.Translator(config()).apply([after_item])
    assert content_hash(after_item) == before


def test_cve_id_and_url_not_mangled(fake_provider):
    """CVE 번호·URL 은 자리표시자로 빼놨다가 원래대로 되돌린다."""
    text = "See CVE-2026-1234 and https://osv.dev/x for details."
    item = finding(summary=text)
    tr.Translator(config()).apply([item])
    assert "CVE-2026-1234" not in fake_provider[0]      # 번역기에는 안 넘어감
    assert "CVE-2026-1234" in item.summary              # 결과에는 살아 있음
    assert "https://osv.dev/x" in item.summary


def test_empty_summary_skipped(fake_provider):
    item = finding(summary="")
    stat = tr.Translator(config()).apply([item])
    assert stat.skipped == 1 and fake_provider == []


def test_failure_falls_back_to_english(monkeypatch):
    def boom(session, text, lang, timeout):
        raise tr.TranslationError("서버 오류")

    monkeypatch.setitem(tr.PROVIDERS, "broken", boom)
    monkeypatch.setattr(tr.time, "sleep", lambda *_: None)
    item = finding()
    stat = tr.Translator(config(provider="broken", max_retries=2)).apply([item])
    assert item.summary == "A flaw was found."      # 영문 그대로
    assert stat.failed == 1


def test_unknown_provider_does_not_crash(fake_provider):
    item = finding()
    stat = tr.Translator(config(provider="없는제공자")).apply([item])
    assert item.summary == "A flaw was found."
    assert stat.failed == 1


def test_long_text_truncated_before_sending(fake_provider):
    item = finding(summary="A" * 3000)
    tr.Translator(config(max_chars=100)).apply([item])
    assert len(fake_provider[0]) == 100


# ==========================================================================
#  캐시
# ==========================================================================
def test_same_text_translated_once_in_one_run(fake_provider):
    items = [finding(cve_id="CVE-2026-0001"), finding(cve_id="CVE-2026-0002")]
    stat = tr.Translator(config()).apply(items)
    assert len(fake_provider) == 1, "같은 문장을 두 번 번역하면 안 된다"
    assert stat.translated == 1 and stat.cached == 1
    assert items[1].summary == "[ko]A flaw was found."


def test_cache_survives_across_runs(tmp_path, fake_provider):
    store = SqliteStore(tmp_path / "t.db")
    tr.Translator(config(), store).apply([finding()])
    assert len(fake_provider) == 1

    second = finding(cve_id="CVE-2026-0002")
    stat = tr.Translator(config(), store).apply([second])
    assert len(fake_provider) == 1, "DB 캐시가 있으면 다시 번역하지 않는다"
    assert stat.cached == 1
    assert second.summary == "[ko]A flaw was found."
    assert store.translation_count() == 1
    store.close()


# ==========================================================================
#  변경 감지 해시는 영문 기준 (번역 켜고 꺼도 '변경'으로 잡히지 않아야 함)
# ==========================================================================
def test_hash_unaffected_by_translation():
    english = finding(summary="A flaw was found.", summary_en="A flaw was found.")
    korean = finding(summary="결함이 발견되었습니다.", summary_en="A flaw was found.")
    assert content_hash(english) == content_hash(korean)


def test_hash_still_changes_when_english_changes():
    before = finding(summary_en="A flaw was found.")
    after = finding(summary_en="A different flaw was found.")
    assert content_hash(before) != content_hash(after)


def test_hash_backward_compatible_with_untranslated_rows():
    """summary_en 이 비어 있던 기존 행도 같은 해시가 나와야 한다(대량 '변경' 방지)."""
    legacy = finding(summary="A flaw was found.", summary_en="")
    migrated = finding(summary="A flaw was found.", summary_en="A flaw was found.")
    assert content_hash(legacy) == content_hash(migrated)


# ==========================================================================
#  DB 저장·마이그레이션
# ==========================================================================
def test_summary_en_persisted(tmp_path, fake_provider):
    store = SqliteStore(tmp_path / "t.db")
    item = finding()
    tr.Translator(config(), store).apply([item])
    store.upsert_findings([item], "R1")
    row = store.fetch_all_cves()[0]
    assert row["summary"] == "[ko]A flaw was found."
    assert row["summary_en"] == "A flaw was found."
    store.close()


def test_migration_adds_column_to_old_db(tmp_path):
    """summary_en 이 없던 예전 DB 를 열어도 자동으로 컬럼이 추가돼야 한다."""
    import sqlite3

    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.execute("""CREATE TABLE cve (
        cve_id TEXT, sw_name TEXT, vendor TEXT, affected_range TEXT,
        fixed_version TEXT, severity TEXT, cvss_score REAL, cvss_vector TEXT,
        published_date TEXT, modified_date TEXT, kev_yn TEXT, summary TEXT,
        reference_url TEXT, source TEXT, ecosystem TEXT, first_seen_run TEXT,
        last_seen_run TEXT, collected_at TEXT, content_hash TEXT,
        PRIMARY KEY (cve_id, sw_name))""")
    old.execute("INSERT INTO cve (cve_id, sw_name, summary) VALUES ('CVE-2026-1','PyTorch','old')")
    old.commit()
    old.close()

    store = SqliteStore(path)                      # 여기서 마이그레이션이 돌아야 한다
    columns = {r["name"] for r in store.conn.execute("PRAGMA table_info(cve)")}
    assert "summary_en" in columns
    assert store.fetch_all_cves()[0]["summary"] == "old"   # 기존 데이터 보존
    store.upsert_findings([finding()], "R1")               # 새 저장도 정상
    store.close()
