"""DB 저장·신규/변경 판정 검증."""
from __future__ import annotations

from src.aicve.normalize import Finding
from src.aicve.scope import resolve_scope
from src.aicve.store import SqliteStore, content_hash, rows_to_findings

from .test_scope import SETTINGS, WATCHLIST


def make_finding(cve="CVE-2026-0001", sw="PyTorch", **kwargs) -> Finding:
    base = dict(
        cve_id=cve, sw_name=sw, source="OSV", vendor="PyTorch Foundation",
        ecosystem="pypi", affected_range="<1.4.2", fixed_version="1.4.2",
        severity="HIGH", cvss_score=7.5, cvss_vector="CVSS:3.1/AV:N",
        published_date="20260801", modified_date="20260802", kev_yn="N",
        summary="테스트 취약점", reference_url="https://example.com",
        collected_at="20260814090000",
    )
    base.update(kwargs)
    return Finding(**base)


def store(tmp_path) -> SqliteStore:
    return SqliteStore(tmp_path / "test.db")


def test_new_then_unchanged_then_updated(tmp_path):
    db = store(tmp_path)
    finding = make_finding()

    first = db.upsert_findings([finding], "20260814090000")
    assert len(first["new"]) == 1 and not first["updated"]

    second = db.upsert_findings([finding], "20260815090000")
    assert not second["new"] and not second["updated"]
    assert len(second["unchanged"]) == 1

    changed = make_finding(severity="CRITICAL", cvss_score=9.8)
    third = db.upsert_findings([changed], "20260816090000")
    assert len(third["updated"]) == 1 and not third["new"]

    rows = db.fetch_all_cves()
    assert len(rows) == 1, "같은 (CVE_ID, SW_NAME) 은 1행으로 유지된다"
    assert rows[0]["severity"] == "CRITICAL"
    assert rows[0]["first_seen_run"] == "20260814090000"   # 최초 발견 회차 보존
    assert rows[0]["last_seen_run"] == "20260816090000"
    db.close()


def test_same_cve_different_sw_are_separate_rows(tmp_path):
    db = store(tmp_path)
    result = db.upsert_findings(
        [make_finding(sw="PyTorch"), make_finding(sw="TensorFlow")], "R1")
    assert len(result["new"]) == 2
    assert len(db.fetch_all_cves()) == 2
    db.close()


def test_content_hash_tracks_five_fields():
    base = make_finding()
    assert content_hash(base) == content_hash(make_finding())
    for field, value in [("affected_range", "<9.9.9"), ("fixed_version", "2.0.0"),
                         ("severity", "LOW"), ("cvss_score", 3.1),
                         ("summary", "다른 내용")]:
        assert content_hash(base) != content_hash(make_finding(**{field: value})), field
    # 해시에 포함되지 않는 필드는 변경으로 보지 않는다
    assert content_hash(base) == content_hash(make_finding(reference_url="https://other"))


def test_run_log_lifecycle(tmp_path):
    db = store(tmp_path)
    scope = resolve_scope(cli={"preset": "daily"}, settings=SETTINGS, watchlist=WATCHLIST)
    db.start_run("R1", scope)
    assert db.fetch_run("R1")["status"] == "RUNNING"

    db.finish_run("R1", status="SUCCESS", total_cnt=3, new_cnt=2, updated_cnt=1,
                  truncated_cnt=5, source_stat={"OSV": 3}, excel_file="CVE_20260814.xls")
    row = db.fetch_run("R1")
    assert row["status"] == "SUCCESS"
    assert row["scope_desc"].startswith("SCOPE ")
    assert row["source_stat"] == '{"OSV": 3}'
    assert row["truncated_cnt"] == 5
    assert db.fetch_runs(10)[0]["run_id"] == "R1"
    db.close()


def test_mail_log(tmp_path):
    db = store(tmp_path)
    db.log_mail("R1", "a@example.com", "제목", "SENT", attach_file="CVE_20260814.xls")
    db.log_mail("R1", "b@example.com", "제목", "FAILED", error_msg="SMTP 오류")
    logs = db.fetch_mail_logs("R1")
    assert [x["status"] for x in logs] == ["SENT", "FAILED"]
    assert db.mail_stat_by_run()["R1"] == {"SENT": 1, "FAILED": 1}
    db.close()


def test_fetch_run_cves_and_roundtrip(tmp_path):
    db = store(tmp_path)
    db.upsert_findings([make_finding(), make_finding(cve="CVE-2026-0002")], "R1")
    rows = db.fetch_run_cves("R1")
    assert len(rows) == 2
    findings = rows_to_findings(rows)
    assert findings[0].cve_id == "CVE-2026-0001"
    assert findings[0].affected_range == "<1.4.2"
    db.close()


def test_stats(tmp_path):
    db = store(tmp_path)
    db.upsert_findings([
        make_finding(cve="CVE-2026-0001", severity="CRITICAL"),
        make_finding(cve="CVE-2026-0002", severity="HIGH"),
        make_finding(cve="CVE-2026-0003", sw="vLLM", severity="HIGH"),
    ], "R1")
    assert db.severity_counts() == {"CRITICAL": 1, "HIGH": 2}
    assert db.sw_counts(10)[0] == {"sw_name": "PyTorch", "cnt": 2}
    assert db.total_cve_count() == 3
    db.close()
