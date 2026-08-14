"""수집 범위(Scope) 확정.

우선순위 :  settings.yml 의 defaults  →  preset  →  CLI/Actions 인자
(뒤가 앞을 덮어쓴다. 값이 비어 있으면(None/"") 덮어쓰지 않는다)

확정된 Scope 객체 하나만 전 모듈에 넘긴다.
다른 모듈은 settings.yml 을 직접 읽지 않는다 —
필요한 설정은 Scope.collect / Scope.output / Scope.mail / Scope.site 로 전달된다.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .logutil import get_logger

log = get_logger("scope")

# 심각도 등급 (숫자가 클수록 심각)
SEVERITY_RANK: Dict[str, int] = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
VALID_SEVERITY = tuple(SEVERITY_RANK) + ("ALL",)
VALID_SOURCES = ("nvd", "osv", "ghsa", "kev")
VALID_GROUPS = ("framework", "serving", "library", "app", "ui", "vectordb", "mlops", "base")
VALID_EXCEL_SCOPE = ("delta", "all")

# settings.yml 의 defaults 가 비어 있어도 동작하도록 하는 최종 기본값
HARD_DEFAULTS: Dict[str, Any] = {
    "lookback_days": 3,
    "date_from": None,
    "date_to": None,
    "min_severity": "MEDIUM",
    "groups": "all",
    "sw_names": None,
    "only_in_use": False,
    "sources": "nvd,osv,ghsa,kev",
    "excel_scope": "delta",
    "max_rows": 300,
}

AXIS_KEYS = tuple(HARD_DEFAULTS)


class ScopeError(ValueError):
    """수집 범위 설정이 잘못됐을 때."""


# --------------------------------------------------------------------------
# 값 파싱 헬퍼
# --------------------------------------------------------------------------
def _is_empty(value: Any) -> bool:
    """CLI/Actions 에서 넘어온 '비어 있는 값'인지. 비면 덮어쓰지 않는다."""
    if value is None:
        return True
    if isinstance(value, str) and value.strip() == "":
        return True
    if isinstance(value, (list, tuple)) and len(value) == 0:
        return True
    return False


def _split_csv(value: Any) -> List[str]:
    """'a, b ,c' → ['a','b','c'].  None/빈문자 → []"""
    if _is_empty(value):
        return []
    if isinstance(value, (list, tuple)):
        items = list(value)
    else:
        items = str(value).split(",")
    return [str(x).strip() for x in items if str(x).strip()]


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "y", "on")


def _to_int(value: Any, key: str) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        raise ScopeError(f"{key} 는 정수여야 합니다: {value!r}")


def _norm_date(value: Any, key: str) -> Optional[str]:
    """'YYYY-MM-DD' 로 정규화. 비었으면 None."""
    if _is_empty(value):
        return None
    text = str(value).strip()
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%Y%m%d"):
        try:
            return datetime.strptime(text, fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    raise ScopeError(f"{key} 형식이 잘못됐습니다(YYYY-MM-DD 이어야 함): {value!r}")


# --------------------------------------------------------------------------
# Scope
# --------------------------------------------------------------------------
@dataclass
class Scope:
    """확정된 수집 범위. 실행 내내 이 객체 하나만 돌려 쓴다."""

    # --- 3.5절 9개 축 ---
    lookback_days: int = 3
    date_from: Optional[str] = None
    date_to: Optional[str] = None
    min_severity: str = "MEDIUM"
    groups: List[str] = field(default_factory=lambda: ["all"])
    sw_names: List[str] = field(default_factory=list)
    only_in_use: bool = False
    sources: List[str] = field(default_factory=lambda: list(VALID_SOURCES))
    excel_scope: str = "delta"
    max_rows: int = 300

    # --- 부가 정보 ---
    preset: Optional[str] = None
    skip_mail: bool = False
    dry_run: bool = False
    targets: List[Dict[str, Any]] = field(default_factory=list)   # 확정된 watchlist 항목
    unmatched_sw: List[str] = field(default_factory=list)          # sw_names 중 못 찾은 이름

    # --- settings.yml 하위 설정 (모듈이 yaml 을 직접 읽지 않게 전달) ---
    collect: Dict[str, Any] = field(default_factory=dict)
    output: Dict[str, Any] = field(default_factory=dict)
    mail: Dict[str, Any] = field(default_factory=dict)
    site: Dict[str, Any] = field(default_factory=dict)

    # ---------------- 기간 ----------------
    @property
    def uses_absolute_range(self) -> bool:
        return bool(self.date_from)

    def date_range(self, today: Optional[date] = None) -> tuple[date, date]:
        """실제 조회 구간 (시작일, 종료일). 양끝 포함."""
        today = today or date.today()
        if self.date_from:
            start = datetime.strptime(self.date_from, "%Y-%m-%d").date()
            end = (datetime.strptime(self.date_to, "%Y-%m-%d").date()
                   if self.date_to else today)
        else:
            end = today
            start = end - timedelta(days=max(self.lookback_days - 1, 0))
        if start > end:
            raise ScopeError(f"시작일({start})이 종료일({end})보다 뒤입니다.")
        return start, end

    # ---------------- 필터 ----------------
    @property
    def min_severity_rank(self) -> int:
        """ALL 이면 -1 (아무것도 거르지 않음)."""
        if self.min_severity == "ALL":
            return -1
        return SEVERITY_RANK[self.min_severity]

    def severity_allowed(self, severity: str, kev: bool = False) -> bool:
        """심각도 하한 통과 여부. KEV 등재 건은 심각도와 무관하게 항상 통과."""
        if kev:
            return True
        if self.min_severity == "ALL":
            return True
        return SEVERITY_RANK.get((severity or "NONE").upper(), 0) >= self.min_severity_rank

    def has_source(self, name: str) -> bool:
        return name.lower() in self.sources

    @property
    def target_names(self) -> List[str]:
        return [t["canonical_name"] for t in self.targets]

    # ---------------- 표기 ----------------
    @property
    def desc(self) -> str:
        """실행 로그 첫 줄 / run_log.scope_desc / 엑셀 META / 메일 본문에 그대로 실리는 한 줄."""
        if self.uses_absolute_range:
            period = f"from={self.date_from} to={self.date_to or date.today().isoformat()}"
        else:
            period = f"lookback={self.lookback_days}"
        return (
            f"SCOPE {period}"
            f" sev>={self.min_severity}"
            f" groups={','.join(self.groups) if self.groups else 'all'}"
            f" sw={','.join(self.sw_names) if self.sw_names else '-'}"
            f" in_use={self.only_in_use}"
            f" src={','.join(self.sources)}"
            f" scope={self.excel_scope}"
            f" max={self.max_rows}"
        )

    def to_dict(self) -> Dict[str, Any]:
        start, end = self.date_range()
        return {
            "lookback_days": self.lookback_days,
            "date_from": self.date_from,
            "date_to": self.date_to,
            "resolved_from": start.isoformat(),
            "resolved_to": end.isoformat(),
            "min_severity": self.min_severity,
            "groups": self.groups,
            "sw_names": self.sw_names,
            "only_in_use": self.only_in_use,
            "sources": self.sources,
            "excel_scope": self.excel_scope,
            "max_rows": self.max_rows,
            "preset": self.preset,
            "skip_mail": self.skip_mail,
            "dry_run": self.dry_run,
            "target_count": len(self.targets),
            "target_names": self.target_names,
            "unmatched_sw": self.unmatched_sw,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=False)

    # 엑셀 META 시트용 (키 순서 고정)
    def meta_items(self) -> List[tuple[str, str]]:
        start, end = self.date_range()
        return [
            ("SCOPE_DESC", self.desc),
            ("DATE_FROM", start.strftime("%Y%m%d")),
            ("DATE_TO", end.strftime("%Y%m%d")),
            ("MIN_SEVERITY", self.min_severity),
            ("GROUPS", ",".join(self.groups) if self.groups else "all"),
            ("SW_NAMES", ",".join(self.sw_names) if self.sw_names else ""),
            ("ONLY_IN_USE", "Y" if self.only_in_use else "N"),
            ("SOURCES", ",".join(self.sources)),
            ("EXCEL_SCOPE", self.excel_scope),
            ("MAX_ROWS", str(self.max_rows)),
        ]


# --------------------------------------------------------------------------
# 로딩 / 병합
# --------------------------------------------------------------------------
def load_yaml(path: str | Path) -> Any:
    path = Path(path)
    if not path.exists():
        raise ScopeError(f"설정 파일을 찾을 수 없습니다: {path}")
    with path.open(encoding="utf-8") as fp:
        return yaml.safe_load(fp) or {}


def load_settings(path: str | Path = "config/settings.yml") -> Dict[str, Any]:
    data = load_yaml(path)
    if not isinstance(data, dict):
        raise ScopeError(f"settings.yml 형식이 잘못됐습니다: {path}")
    return data


def load_watchlist(path: str | Path = "config/watchlist.yml") -> List[Dict[str, Any]]:
    data = load_yaml(path)
    if not isinstance(data, list):
        raise ScopeError(f"watchlist.yml 은 목록(list) 이어야 합니다: {path}")
    for item in data:
        if not isinstance(item, dict) or not item.get("canonical_name"):
            raise ScopeError(f"watchlist 항목에 canonical_name 이 없습니다: {item!r}")
    return data


def merge_layers(defaults: Dict[str, Any],
                 preset: Optional[Dict[str, Any]],
                 cli: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """defaults → preset → cli 순으로 덮어쓴다. 빈 값은 무시."""
    merged: Dict[str, Any] = dict(HARD_DEFAULTS)
    for layer in (defaults or {}, preset or {}, cli or {}):
        for key, value in (layer or {}).items():
            if key not in AXIS_KEYS:
                continue
            if _is_empty(value):
                continue
            merged[key] = value
    return merged


def select_targets(watchlist: List[Dict[str, Any]],
                   sw_names: List[str],
                   groups: List[str],
                   only_in_use: bool) -> tuple[List[Dict[str, Any]], List[str]]:
    """감시 대상 확정. sw_names 가 지정되면 groups·only_in_use 는 무시한다(가장 좁은 조건이 이긴다).

    돌려주는 값: (선택된 항목들, 매칭 실패한 sw_name 목록)
    """
    enabled = [w for w in watchlist if w.get("enabled", True)]

    if sw_names:
        wanted = [s.strip().lower() for s in sw_names if s.strip()]
        chosen: List[Dict[str, Any]] = []
        matched: set[str] = set()
        for item in enabled:
            keys = {str(item["canonical_name"]).lower()}
            keys |= {str(a).lower() for a in (item.get("aliases") or [])}
            hit = [w for w in wanted if w in keys]
            if hit:
                chosen.append(item)
                matched.update(hit)
        unmatched = [w for w in wanted if w not in matched]
        return chosen, unmatched

    selected = enabled
    if groups and "all" not in [g.lower() for g in groups]:
        gset = {g.lower() for g in groups}
        selected = [w for w in selected if str(w.get("group", "")).lower() in gset]
    if only_in_use:
        selected = [w for w in selected if _to_bool(w.get("in_use", False))]
    return list(selected), []


def resolve_scope(cli: Optional[Dict[str, Any]] = None,
                  settings: Optional[Dict[str, Any]] = None,
                  watchlist: Optional[List[Dict[str, Any]]] = None,
                  settings_path: str | Path = "config/settings.yml",
                  watchlist_path: str | Path = "config/watchlist.yml") -> Scope:
    """settings → preset → CLI 를 병합해 Scope 를 확정한다."""
    cli = dict(cli or {})
    if settings is None:
        settings = load_settings(settings_path)
    if watchlist is None:
        watchlist = load_watchlist(watchlist_path)

    defaults = settings.get("defaults") or {}
    presets = settings.get("presets") or {}

    preset_name = cli.get("preset")
    preset_values: Optional[Dict[str, Any]] = None
    if not _is_empty(preset_name):
        preset_name = str(preset_name).strip()
        if preset_name not in presets:
            raise ScopeError(
                f"알 수 없는 preset 입니다: {preset_name} "
                f"(사용 가능: {', '.join(presets) or '없음'})")
        preset_values = presets[preset_name] or {}
    else:
        preset_name = None

    merged = merge_layers(defaults, preset_values, cli)

    # ---- 값 검증·정규화 ----
    lookback = _to_int(merged["lookback_days"], "lookback_days")
    if lookback < 1:
        raise ScopeError(f"lookback_days 는 1 이상이어야 합니다: {lookback}")

    date_from = _norm_date(merged["date_from"], "date_from")
    date_to = _norm_date(merged["date_to"], "date_to")
    if date_to and not date_from:
        # 종료일만 준 경우 lookback 만큼 거슬러 올라간다
        end = datetime.strptime(date_to, "%Y-%m-%d").date()
        date_from = (end - timedelta(days=max(lookback - 1, 0))).isoformat()

    min_severity = str(merged["min_severity"]).strip().upper()
    if min_severity not in VALID_SEVERITY:
        raise ScopeError(
            f"min_severity 값이 잘못됐습니다: {merged['min_severity']!r} "
            f"(사용 가능: {', '.join(VALID_SEVERITY)})")

    groups = [g.lower() for g in _split_csv(merged["groups"])] or ["all"]
    for g in groups:
        if g != "all" and g not in VALID_GROUPS:
            raise ScopeError(
                f"알 수 없는 group 입니다: {g} (사용 가능: {', '.join(VALID_GROUPS)})")

    sw_names = _split_csv(merged["sw_names"])
    only_in_use = _to_bool(merged["only_in_use"])

    sources = [s.lower() for s in _split_csv(merged["sources"])] or list(VALID_SOURCES)
    for s in sources:
        if s not in VALID_SOURCES:
            raise ScopeError(
                f"알 수 없는 source 입니다: {s} (사용 가능: {', '.join(VALID_SOURCES)})")

    excel_scope = str(merged["excel_scope"]).strip().lower()
    if excel_scope not in VALID_EXCEL_SCOPE:
        raise ScopeError(
            f"excel_scope 는 delta 또는 all 이어야 합니다: {merged['excel_scope']!r}")

    max_rows = _to_int(merged["max_rows"], "max_rows")
    if max_rows < 1:
        raise ScopeError(f"max_rows 는 1 이상이어야 합니다: {max_rows}")

    targets, unmatched = select_targets(watchlist, sw_names, groups, only_in_use)
    if unmatched:
        log.warning("watchlist 에서 찾지 못한 S/W 이름: %s", ", ".join(unmatched))

    scope = Scope(
        lookback_days=lookback,
        date_from=date_from,
        date_to=date_to,
        min_severity=min_severity,
        groups=groups,
        sw_names=sw_names,
        only_in_use=only_in_use,
        sources=sources,
        excel_scope=excel_scope,
        max_rows=max_rows,
        preset=preset_name,
        skip_mail=_to_bool(cli.get("skip_mail", False)),
        dry_run=_to_bool(cli.get("dry_run", False)),
        targets=targets,
        unmatched_sw=unmatched,
        collect=settings.get("collect") or {},
        output=settings.get("output") or {},
        mail=settings.get("mail") or {},
        site=settings.get("site") or {},
    )
    scope.date_range()  # 구간 유효성 즉시 검증
    return scope
