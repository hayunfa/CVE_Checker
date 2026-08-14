"""메일 발송.

  - 수신자는 mail_list.txt (1줄 1주소, '#' 주석·빈 줄 무시, 형식 검증, 중복 제거)
  - 개별 발송(To 에 1명씩) — 수신자 주소가 서로 노출되지 않게 한다
  - 실패한 주소만 최대 2회 재시도
  - 신규 0건이면 발송하지 않고 mail_log.status='SKIPPED'
  - 첨부는 CVE_YYYYMMDD.xls (5MB 초과 시 생략하고 Pages 링크로 대체)
  - 발송 결과는 전건 mail_log 에 기록

SMTP 설정은 환경변수(=GitHub Secrets): SMTP_HOST/SMTP_PORT/SMTP_USER/SMTP_PASS/MAIL_FROM
"""
from __future__ import annotations

import os
import re
import smtplib
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime
from email.message import EmailMessage
from email.utils import formataddr, parseaddr
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .excel import ExcelResult
from .logutil import get_logger
from .normalize import Finding, sort_findings
from .scope import SEVERITY_RANK

log = get_logger("mailer")

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
SEVERITY_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE")


@dataclass
class MailResult:
    subject: str = ""
    sent: List[str] = field(default_factory=list)
    failed: List[Tuple[str, str]] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    attached: bool = False
    preview_path: Optional[Path] = None
    reason: str = ""

    @property
    def ok(self) -> bool:
        return not self.failed

    def summary(self) -> str:
        parts = [f"발송 {len(self.sent)}건"]
        if self.failed:
            parts.append(f"실패 {len(self.failed)}건")
        if self.skipped:
            parts.append(f"생략 {len(self.skipped)}건")
        return " / ".join(parts)


# ==========================================================================
#  수신자
# ==========================================================================
def load_recipients(path: str | Path = "mail_list.txt") -> List[str]:
    """1줄 1주소. '#' 주석·빈 줄 무시, 앞뒤 공백 제거, 형식 검증, 중복 제거(순서 유지)."""
    path = Path(path)
    if not path.exists():
        log.warning("수신자 목록 파일이 없습니다: %s", path)
        return []

    recipients: List[str] = []
    seen: set = set()
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        address = parseaddr(line)[1].strip() or line
        if not EMAIL_RE.match(address):
            log.warning("메일 주소 형식이 잘못돼 건너뜁니다 (%s %d행): %s",
                        path.name, line_no, address)
            continue
        key = address.lower()
        if key in seen:
            continue
        seen.add(key)
        recipients.append(address)

    log.info("수신자 %d명 (%s)", len(recipients), path.name)
    return recipients


# ==========================================================================
#  본문
# ==========================================================================
def severity_stats(findings: Sequence[Finding]) -> Dict[str, int]:
    stats = {level: 0 for level in SEVERITY_LEVELS}
    for finding in findings:
        level = (finding.severity or "NONE").upper()
        stats[level] = stats.get(level, 0) + 1
    return stats


def build_subject(prefix: str, run_date: str, new_cnt: int,
                  stats: Dict[str, int]) -> str:
    """[AI OSS 취약점] YYYY-MM-DD 신규 N건 (Critical A / High B)"""
    return (f"{prefix} {run_date} 신규 {new_cnt}건 "
            f"(Critical {stats.get('CRITICAL', 0)} / High {stats.get('HIGH', 0)})")


def _env(template_dir: str | Path) -> Environment:
    return Environment(
        loader=FileSystemLoader(str(template_dir), encoding="utf-8"),
        autoescape=select_autoescape(["html", "xml", "j2"]),
        trim_blocks=True, lstrip_blocks=True,
    )


def render_body(scope, findings: Sequence[Finding], run_id: str,
                excel: Optional[ExcelResult] = None,
                new_cnt: int = 0, updated_cnt: int = 0, truncated_cnt: int = 0,
                source_stat: Optional[Dict[str, Any]] = None,
                attached: bool = True,
                template_dir: str | Path = "templates",
                all_findings: Optional[Sequence[Finding]] = None) -> Tuple[str, str]:
    """(HTML 본문, 텍스트 대체본).

    findings     : 엑셀에 실제로 담긴 목록 (max_rows 로 잘린 뒤)
    all_findings : 자르기 전 전체 목록. 심각도 집계·합계는 이쪽 기준으로 낸다
                   (제목의 '신규 N건' 과 숫자가 어긋나지 않게).
    """
    ordered = sort_findings(findings)
    top_n = int(scope.mail.get("top_n", 10))
    stats = severity_stats(all_findings if all_findings is not None else ordered)
    base_url = (scope.site.get("base_url") or os.environ.get("SITE_BASE_URL", "")).rstrip("/")

    context = {
        "run_id": run_id,
        "date_str": f"{run_id[:4]}-{run_id[4:6]}-{run_id[6:8]}" if len(run_id) >= 8
                    else datetime.now().strftime("%Y-%m-%d"),
        "scope_desc": scope.desc,
        "stats": stats,
        "total_cnt": len(all_findings) if all_findings is not None else len(ordered),
        "excel_cnt": len(ordered),
        "new_cnt": new_cnt,
        "updated_cnt": updated_cnt,
        "truncated_cnt": truncated_cnt,
        "max_rows": scope.max_rows,
        "kev_items": [f for f in ordered if f.kev_yn == "Y"][:20],
        "top_items": ordered[:top_n],
        "excel_name": excel.file_name if excel else "",
        "excel_url": f"{base_url}/output/{excel.file_name}" if base_url and excel else "",
        "site_url": base_url or "",
        "run_url": f"{base_url}/runs/{run_id}.html" if base_url else "",
        "attached": attached,
        "max_attach_mb": scope.mail.get("max_attach_mb", 5),
        "source_stat": source_stat or {},
    }

    html = _env(template_dir).get_template("mail.html.j2").render(**context)
    return html, render_text(context, ordered[:top_n])


def render_text(context: Dict[str, Any], top_items: Sequence[Finding]) -> str:
    """HTML 을 못 보는 클라이언트용 대체본."""
    lines = [
        "AI 오픈소스 신규 취약점 알림",
        f"{context['date_str']} 수집 · 실행번호 {context['run_id']}",
        "",
        f"[수집 조건] {context['scope_desc']}",
        "",
        "심각도별 건수: " + " / ".join(
            f"{level} {context['stats'].get(level, 0)}" for level in SEVERITY_LEVELS),
        f"합계 {context['total_cnt']}건 (신규 {context['new_cnt']} / 변경 {context['updated_cnt']})",
    ]
    if context["truncated_cnt"]:
        lines.append(f"※ 최대 행수({context['max_rows']}) 초과로 "
                     f"{context['truncated_cnt']}건은 엑셀에서 제외됨 "
                     f"(첨부 엑셀 {context['excel_cnt']}건)")
    if context["kev_items"]:
        lines += ["", f"[실제 악용 확인(CISA KEV) {len(context['kev_items'])}건 — 우선 조치]"]
        for item in context["kev_items"]:
            lines.append(f"  - {item.cve_id} {item.sw_name} "
                         f"{item.affected_range} → {item.fixed_version or '조치버전 미상'}")
    lines += ["", f"[심각도 상위 {len(top_items)}건]"]
    for item in top_items:
        mark = " [KEV]" if item.kev_yn == "Y" else ""
        lines.append(f"  - {item.cve_id} {item.sw_name} {item.severity} "
                     f"{item.cvss_score or '-'} {item.affected_range} "
                     f"→ {item.fixed_version or '조치버전 미상'}{mark}")
    if context["attached"] and context["excel_name"]:
        lines += ["", f"첨부: {context['excel_name']} (내부망 반입용 정본)"]
    elif context["excel_url"]:
        lines += ["", f"엑셀 내려받기: {context['excel_url']}"]
    if context["site_url"]:
        lines += [f"열람 페이지: {context['site_url']}"]
    return "\n".join(lines)


# ==========================================================================
#  발송
# ==========================================================================
def smtp_config() -> Dict[str, Any]:
    return {
        "host": os.environ.get("SMTP_HOST", "").strip(),
        "port": int(os.environ.get("SMTP_PORT", "587") or 587),
        "user": os.environ.get("SMTP_USER", "").strip(),
        "password": os.environ.get("SMTP_PASS", ""),
        "sender": (os.environ.get("MAIL_FROM", "").strip()
                   or os.environ.get("SMTP_USER", "").strip()),
    }


def _connect(config: Dict[str, Any], timeout: int = 30):
    """465 는 SSL, 그 외는 STARTTLS."""
    if config["port"] == 465:
        server = smtplib.SMTP_SSL(config["host"], config["port"],
                                  timeout=timeout, context=ssl.create_default_context())
    else:
        server = smtplib.SMTP(config["host"], config["port"], timeout=timeout)
        server.ehlo()
        try:
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
        except smtplib.SMTPException:
            log.warning("STARTTLS 미지원 서버 — 평문으로 계속합니다.")
    if config["user"]:
        server.login(config["user"], config["password"])
    return server


def _build_message(subject: str, sender: str, recipient: str,
                   html: str, text: str,
                   attachments: Sequence[Path]) -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = subject
    name, address = parseaddr(sender)
    message["From"] = formataddr((name, address)) if name else address
    message["To"] = recipient
    message["Date"] = datetime.now().astimezone().strftime("%a, %d %b %Y %H:%M:%S %z")
    message.set_content(text)
    message.add_alternative(html, subtype="html")
    for path in attachments:
        message.add_attachment(
            path.read_bytes(),
            maintype="application",
            subtype="vnd.ms-excel" if path.suffix == ".xls" else "octet-stream",
            filename=path.name)
    return message


def _attachments_for(scope, excel: Optional[ExcelResult]) -> Tuple[List[Path], bool]:
    """첨부 목록과 첨부 여부. 합계가 max_attach_mb 를 넘으면 첨부하지 않는다."""
    if not excel or not excel.xls_path.exists():
        return [], False
    limit = float(scope.mail.get("max_attach_mb", 5)) * 1024 * 1024
    size = excel.xls_path.stat().st_size
    if size > limit:
        log.warning("첨부 %s 가 %.1fMB 로 한도를 넘어 생략합니다.",
                    excel.file_name, size / 1024 / 1024)
        return [], False
    return [excel.xls_path], True


def send_mail(scope, store, run_id: str, findings: Sequence[Finding],
              excel: Optional[ExcelResult] = None,
              new_cnt: int = 0, updated_cnt: int = 0, truncated_cnt: int = 0,
              source_stat: Optional[Dict[str, Any]] = None,
              recipients_path: str | Path = "mail_list.txt",
              template_dir: str | Path = "templates",
              preview_dir: str | Path = "output",
              all_findings: Optional[Sequence[Finding]] = None) -> MailResult:
    """메일을 개별 발송하고 결과를 mail_log 에 남긴다."""
    result = MailResult()
    recipients = load_recipients(recipients_path)
    stats = severity_stats(all_findings if all_findings is not None else findings)
    run_date = (f"{run_id[:4]}-{run_id[4:6]}-{run_id[6:8]}"
                if len(run_id) >= 8 else datetime.now().strftime("%Y-%m-%d"))
    result.subject = build_subject(
        str(scope.mail.get("subject_prefix", "[AI OSS 취약점]")),
        run_date, new_cnt or len(findings), stats)

    attachments, attached = _attachments_for(scope, excel)
    result.attached = attached
    html, text = render_body(scope, findings, run_id, excel, new_cnt, updated_cnt,
                             truncated_cnt, source_stat, attached, template_dir,
                             all_findings)

    def record(status: str, error: str = "") -> None:
        for address in recipients or ["(수신자 없음)"]:
            store.log_mail(run_id, address, result.subject, status,
                           error_msg=error,
                           attach_file=excel.file_name if excel else "")

    # ---- 발송하지 않는 경우들 ----
    if scope.skip_mail:
        result.reason = "--skip-mail 옵션으로 발송을 생략했습니다."
        result.skipped = list(recipients)
        record("SKIPPED", result.reason)
        log.info(result.reason)
        return result

    if not findings and not scope.mail.get("send_when_empty", False):
        result.reason = "신규·변경 건이 0건이라 발송하지 않았습니다."
        result.skipped = list(recipients)
        record("SKIPPED", result.reason)
        log.info(result.reason)
        return result

    if not recipients:
        result.reason = "수신자가 없습니다 (mail_list.txt 확인)."
        record("SKIPPED", result.reason)
        log.warning(result.reason)
        return result

    if scope.dry_run:
        preview = Path(preview_dir) / f"mail_preview_{run_id}.html"
        preview.parent.mkdir(parents=True, exist_ok=True)
        preview.write_text(html, encoding="utf-8")
        preview.with_suffix(".txt").write_text(text, encoding="utf-8")
        result.preview_path = preview
        result.reason = f"--dry-run: 발송 없이 미리보기만 저장했습니다 ({preview})"
        result.skipped = list(recipients)
        record("SKIPPED", result.reason)
        log.info(result.reason)
        log.info("메일 제목: %s", result.subject)
        return result

    config = smtp_config()
    if not config["host"] or not config["sender"]:
        result.reason = "SMTP 설정(SMTP_HOST/MAIL_FROM)이 없어 발송을 건너뜁니다."
        result.skipped = list(recipients)
        record("SKIPPED", result.reason)
        log.warning(result.reason)
        return result

    # ---- 실제 발송 (개별 발송 + 실패분 재시도) ----
    timeout = int(scope.collect.get("timeout", 30))
    max_retry = int(scope.mail.get("retry", 2))
    pending = list(recipients)
    errors: Dict[str, str] = {}

    for attempt in range(1, max_retry + 2):        # 최초 1회 + 재시도 max_retry 회
        if not pending:
            break
        if attempt > 1:
            log.info("실패한 %d개 주소 재시도 (%d/%d)", len(pending), attempt - 1, max_retry)
            time.sleep(min(5 * attempt, 20))

        try:
            server = _connect(config, timeout)
        except Exception as exc:
            message = f"SMTP 접속 실패: {type(exc).__name__}: {exc}"
            log.error(message)
            for address in pending:
                errors[address] = message
            continue

        still_pending: List[str] = []
        try:
            for address in pending:
                try:
                    server.send_message(
                        _build_message(result.subject, config["sender"], address,
                                       html, text, attachments))
                    result.sent.append(address)
                    errors.pop(address, None)
                    store.log_mail(run_id, address, result.subject, "SENT",
                                   attach_file=excel.file_name if excel else "")
                    log.info("발송 완료: %s", address)
                except Exception as exc:
                    errors[address] = f"{type(exc).__name__}: {exc}"
                    still_pending.append(address)
                    log.warning("발송 실패: %s (%s)", address, errors[address])
        finally:
            try:
                server.quit()
            except Exception:
                pass
        pending = still_pending

    for address in pending:
        error = errors.get(address, "알 수 없는 오류")
        result.failed.append((address, error))
        store.log_mail(run_id, address, result.subject, "FAILED", error_msg=error,
                       attach_file=excel.file_name if excel else "")

    log.info("메일 %s", result.summary())
    return result
