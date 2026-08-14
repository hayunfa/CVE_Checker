"""메일 본문·수신자 처리와 열람 페이지 생성 검증 (실제 발송·네트워크 없음)."""
from __future__ import annotations

import html as html_module
import json

from src.aicve.excel import write_excel
from src.aicve.mailer import (
    build_subject,
    load_recipients,
    render_body,
    send_mail,
    severity_stats,
)
from src.aicve.normalize import Finding
from src.aicve.scope import resolve_scope
from src.aicve.site import build_site
from src.aicve.store import SqliteStore

from .test_excel_spec import sample_findings
from .test_scope import SETTINGS, WATCHLIST

RUN_ID = "20260814090000"


def scope_for(cli=None):
    return resolve_scope(cli=cli or {"preset": "daily"},
                         settings=SETTINGS, watchlist=WATCHLIST)


# ==========================================================================
#  수신자 목록
# ==========================================================================
def test_load_recipients_filters_and_dedups(tmp_path):
    path = tmp_path / "mail_list.txt"
    path.write_text(
        "# 주석 줄\n"
        "\n"
        "  a@example.com  \n"          # 앞뒤 공백 제거
        "A@Example.com\n"              # 대소문자 다른 중복
        "b@example.com # 뒤쪽 주석\n"
        "형식이_잘못된주소\n"           # 형식 오류 → 제외
        "no-at-sign.com\n"             # 형식 오류 → 제외
        "c@example.com\n",
        encoding="utf-8")
    assert load_recipients(path) == ["a@example.com", "b@example.com", "c@example.com"]


def test_load_recipients_missing_file(tmp_path):
    assert load_recipients(tmp_path / "없는파일.txt") == []


def test_real_mail_list_parses():
    assert all("@" in a for a in load_recipients("mail_list.txt"))


# ==========================================================================
#  제목 / 통계
# ==========================================================================
def test_subject_format():
    stats = {"CRITICAL": 3, "HIGH": 5}
    subject = build_subject("[AI OSS 취약점]", "2026-08-14", 12, stats)
    assert subject == "[AI OSS 취약점] 2026-08-14 신규 12건 (Critical 3 / High 5)"


def test_severity_stats():
    assert severity_stats(sample_findings()) == {
        "CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "NONE": 1}


# ==========================================================================
#  본문 렌더링
# ==========================================================================
def rendered(text: str) -> str:
    """HTML 엔티티를 풀어 화면에 보이는 문자열로 되돌린다.

    SCOPE 문자열의 '>=' 는 HTML 에서 '&gt;=' 로 이스케이프되지만
    사용자에게 보이는 값은 원본과 같아야 한다.
    """
    return html_module.unescape(text)


def test_render_body_contains_scope_and_kev():
    scope = scope_for()
    html, text = render_body(scope, sample_findings(), RUN_ID,
                             new_cnt=2, updated_cnt=1, truncated_cnt=5)
    assert scope.desc in rendered(html), "메일 본문 상단에 SCOPE 한 줄이 그대로 실려야 한다"
    assert scope.desc in text
    assert "CISA KEV" in html and "CVE-2026-0001" in html      # KEV 건 강조
    assert "5건은 엑셀에서 제외" in text                        # 잘린 건수 명시
    assert "[KEV]" in text


def test_render_body_stats_use_full_set_not_truncated():
    """제목·요약 숫자는 자르기 전 전체 기준이어야 한다."""
    everything = sample_findings()
    html, text = render_body(scope_for(), everything[:1], RUN_ID,
                             new_cnt=3, truncated_cnt=2, all_findings=everything)
    assert "합계 3건" in text          # 1건이 아니라 3건
    assert "첨부 엑셀 1건" in text


def test_render_body_escapes_html():
    findings = [Finding(cve_id="CVE-2026-9999", sw_name="<script>alert(1)</script>",
                        source="OSV", severity="HIGH", cvss_score=7.0)]
    html, _ = render_body(scope_for(), findings, RUN_ID)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# ==========================================================================
#  발송 경로 (SMTP 접속 없음)
# ==========================================================================
def test_skip_mail_records_skipped(tmp_path):
    store = SqliteStore(tmp_path / "t.db")
    scope = scope_for()
    scope.skip_mail = True
    store.start_run(RUN_ID, scope)
    result = send_mail(scope, store, RUN_ID, sample_findings(),
                       recipients_path="mail_list.txt")
    assert not result.sent and result.skipped
    assert {r["status"] for r in store.fetch_mail_logs(RUN_ID)} == {"SKIPPED"}
    store.close()


def test_empty_findings_not_sent(tmp_path):
    """신규 0건이면 발송하지 않고 SKIPPED 를 남긴다 (send_when_empty: false)."""
    store = SqliteStore(tmp_path / "t.db")
    scope = scope_for()
    store.start_run(RUN_ID, scope)
    result = send_mail(scope, store, RUN_ID, [], recipients_path="mail_list.txt")
    assert not result.sent
    assert "0건" in result.reason
    logs = store.fetch_mail_logs(RUN_ID)
    assert logs and all(r["status"] == "SKIPPED" for r in logs)
    store.close()


def test_dry_run_writes_preview(tmp_path):
    store = SqliteStore(tmp_path / "t.db")
    scope = scope_for()
    scope.dry_run = True
    store.start_run(RUN_ID, scope)
    result = send_mail(scope, store, RUN_ID, sample_findings(),
                       recipients_path="mail_list.txt", preview_dir=tmp_path)
    assert result.preview_path.exists()
    assert result.preview_path.with_suffix(".txt").exists()
    assert scope.desc in rendered(result.preview_path.read_text(encoding="utf-8"))
    assert not result.sent
    store.close()


def test_attachment_skipped_when_too_large(tmp_path):
    store = SqliteStore(tmp_path / "t.db")
    scope = scope_for()
    scope.dry_run = True
    scope.mail = dict(scope.mail, max_attach_mb=0.000001)   # 사실상 0
    excel = write_excel(sample_findings(), scope, RUN_ID, out_dir=tmp_path,
                        run_date="20260814")
    store.start_run(RUN_ID, scope)
    result = send_mail(scope, store, RUN_ID, sample_findings(), excel,
                       recipients_path="mail_list.txt", preview_dir=tmp_path)
    assert result.attached is False
    assert "초과해 생략" in result.preview_path.read_text(encoding="utf-8")
    store.close()


# ==========================================================================
#  열람 페이지
# ==========================================================================
def build_docs(tmp_path):
    store = SqliteStore(tmp_path / "t.db")
    scope = scope_for()
    store.start_run(RUN_ID, scope)
    store.upsert_findings(sample_findings(), RUN_ID)
    store.log_mail(RUN_ID, "a@example.com", "제목", "SENT")
    store.log_mail(RUN_ID, "b@example.com", "제목", "FAILED", error_msg="SMTP 오류")
    excel = write_excel(sample_findings(), scope, RUN_ID, out_dir=tmp_path / "output",
                        new_cnt=3, run_date="20260814")
    store.finish_run(RUN_ID, status="SUCCESS", total_cnt=3, new_cnt=3, updated_cnt=0,
                     source_stat={"OSV": 3, "GHSA": "FAILED: 토큰 없음"},
                     excel_file=excel.file_name)
    docs = tmp_path / "docs"
    build_site(scope, store, RUN_ID, excel, docs_dir=docs)
    store.close()
    return docs, scope


def test_site_files_created(tmp_path):
    docs, _ = build_docs(tmp_path)
    for relative in ("index.html", f"runs/{RUN_ID}.html", "cve/index.html",
                     "data/latest.json", "data/all.json", ".nojekyll",
                     "output/CVE_20260814.xls"):
        assert (docs / relative).exists(), relative


def test_index_shows_scope_and_run(tmp_path):
    docs, scope = build_docs(tmp_path)
    html = rendered((docs / "index.html").read_text(encoding="utf-8"))
    assert scope.desc in html               # 적용 SCOPE 가 실행 이력에 보여야 한다
    assert RUN_ID in html
    assert "CVE_20260814.xls" in html
    assert "OSV=3" in html                  # 소스별 수집 건수
    assert "PyTorch" in html


def test_run_detail_has_mail_log(tmp_path):
    docs, _ = build_docs(tmp_path)
    html = (docs / "runs" / f"{RUN_ID}.html").read_text(encoding="utf-8")
    assert "a@example.com" in html and "SENT" in html
    assert "SMTP 오류" in html
    assert "CVE-2026-0001" in html


def test_cve_search_page_embeds_data(tmp_path):
    docs, _ = build_docs(tmp_path)
    html = (docs / "cve" / "index.html").read_text(encoding="utf-8")
    assert "const DATA = [" in html
    assert "CVE-2026-0002" in html
    assert "심각도 전체" in html            # 필터 UI
    assert "cdn" not in html.lower()        # 외부 CDN 의존 없음
    assert "<script src=" not in html


def test_json_outputs_valid(tmp_path):
    docs, _ = build_docs(tmp_path)
    latest = json.loads((docs / "data" / "latest.json").read_text(encoding="utf-8"))
    every = json.loads((docs / "data" / "all.json").read_text(encoding="utf-8"))
    assert latest["run_id"] == RUN_ID and latest["count"] == 3
    assert every["count"] == 3
    assert every["cves"][0]["cve_id"] == "CVE-2026-0001"


def test_empty_delta_does_not_overwrite_existing_excel(tmp_path, monkeypatch):
    """같은 날 두 번째 실행(신규 0건)이 오전에 만든 엑셀을 빈 파일로 덮어쓰면 안 된다."""
    from src.aicve.main import build_parser, run

    out_dir = tmp_path / "output"
    scope = scope_for()
    morning = write_excel(sample_findings(), scope, "20260814060000",
                          out_dir=out_dir, new_cnt=3, run_date="20260814")
    before = morning.xls_path.read_bytes()

    # 수집은 하지 않고(대상 0건이 아니도록 sw-names 지정) 소스만 비활성화한 상태를 흉내낸다
    monkeypatch.setattr("src.aicve.main.collect_all",
                        lambda scope: ([], set(), {"OSV": 0}, []))
    args = build_parser().parse_args([
        "--sw-names", "PyTorch", "--db", str(tmp_path / "t.db"),
        "--out-dir", str(out_dir), "--docs-dir", str(tmp_path / "docs"),
        "--mail-list", "mail_list.txt", "--skip-mail", "--skip-site",
    ])
    assert run(args) == 0
    assert morning.xls_path.read_bytes() == before, "기존 엑셀이 덮어써졌다"


def test_site_survives_empty_database(tmp_path):
    """수집 결과가 하나도 없어도 페이지 생성이 깨지지 않아야 한다."""
    store = SqliteStore(tmp_path / "empty.db")
    docs = tmp_path / "docs"
    build_site(scope_for(), store, None, None, docs_dir=docs)
    assert (docs / "index.html").exists()
    assert "실행 이력이 없습니다" in (docs / "index.html").read_text(encoding="utf-8")
    store.close()
