"""수집 범위(Scope) 확정 검증.

핵심 3가지
  1. settings.yml → preset → CLI 순으로 덮어쓰는가
  2. 빈 값("" / None)이 앞 단계 값을 덮어쓰지 않는가
  3. sw_names 가 groups·only_in_use 를 이기는가 (가장 좁은 조건이 이긴다)
"""
from __future__ import annotations

from datetime import date, timedelta

import pytest

from src.aicve.scope import (
    Scope,
    ScopeError,
    load_settings,
    load_watchlist,
    merge_layers,
    resolve_scope,
    select_targets,
)

# --------------------------------------------------------------------------
#  테스트용 고정 설정 (실제 파일에 의존하지 않는다)
# --------------------------------------------------------------------------
SETTINGS = {
    "defaults": {
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
    },
    "presets": {
        "daily": {"lookback_days": 3, "min_severity": "MEDIUM",
                  "excel_scope": "delta", "max_rows": 300},
        "urgent": {"lookback_days": 1, "min_severity": "HIGH",
                   "excel_scope": "delta", "max_rows": 50},
        "in_use": {"lookback_days": 7, "min_severity": "LOW",
                   "only_in_use": True, "max_rows": 200},
        "monthly": {"lookback_days": 30, "min_severity": "HIGH",
                    "excel_scope": "all", "max_rows": 1000},
        "backfill": {"date_from": "2026-01-01", "min_severity": "HIGH",
                     "excel_scope": "all", "max_rows": 5000},
    },
    "collect": {"timeout": 30},
    "output": {"summary_max_len": 1000},
    "mail": {"send_when_empty": False},
    "site": {"recent_runs": 30},
}

WATCHLIST = [
    {"canonical_name": "PyTorch", "aliases": ["torch"], "ecosystem": "pypi",
     "group": "framework", "enabled": True, "in_use": True},
    {"canonical_name": "TensorFlow", "aliases": ["tensorflow"], "ecosystem": "pypi",
     "group": "framework", "enabled": True, "in_use": False},
    {"canonical_name": "vLLM", "aliases": ["vllm"], "ecosystem": "pypi",
     "group": "serving", "enabled": True, "in_use": True},
    {"canonical_name": "Ollama", "aliases": ["ollama"], "ecosystem": "github",
     "group": "serving", "enabled": True, "in_use": False},
    {"canonical_name": "Gradio", "aliases": ["gradio"], "ecosystem": "pypi",
     "group": "ui", "enabled": True, "in_use": True},
    {"canonical_name": "폐기예정SW", "aliases": [], "ecosystem": "pypi",
     "group": "ui", "enabled": False, "in_use": True},
]


def build(cli=None) -> Scope:
    return resolve_scope(cli=cli or {}, settings=SETTINGS, watchlist=WATCHLIST)


# ==========================================================================
#  1. 우선순위: settings → preset → CLI
# ==========================================================================
def test_defaults_only():
    scope = build()
    assert scope.lookback_days == 3
    assert scope.min_severity == "MEDIUM"
    assert scope.excel_scope == "delta"
    assert scope.max_rows == 300
    assert scope.sources == ["nvd", "osv", "ghsa", "kev"]
    assert scope.groups == ["all"]
    assert scope.preset is None


def test_preset_overrides_defaults():
    scope = build({"preset": "urgent"})
    assert scope.lookback_days == 1        # 3 → 1
    assert scope.min_severity == "HIGH"    # MEDIUM → HIGH
    assert scope.max_rows == 50
    assert scope.preset == "urgent"


def test_cli_overrides_preset():
    scope = build({"preset": "urgent", "lookback_days": 14, "min_severity": "LOW"})
    assert scope.lookback_days == 14       # preset(1) 을 CLI 가 덮어씀
    assert scope.min_severity == "LOW"
    assert scope.max_rows == 50            # CLI 가 안 준 값은 preset 유지


def test_cli_overrides_defaults_without_preset():
    scope = build({"max_rows": 7, "excel_scope": "all"})
    assert scope.max_rows == 7
    assert scope.excel_scope == "all"
    assert scope.lookback_days == 3        # 나머지는 기본값


def test_full_priority_chain():
    """3계층이 한 번에 겹칠 때 최종 승자 확인."""
    scope = build({"preset": "monthly", "max_rows": 42})
    assert scope.lookback_days == 30       # preset (defaults 3 을 이김)
    assert scope.excel_scope == "all"      # preset
    assert scope.max_rows == 42            # CLI (preset 1000 을 이김)
    assert scope.sources == ["nvd", "osv", "ghsa", "kev"]  # defaults


# ==========================================================================
#  2. 빈 값은 덮어쓰지 않는다
# ==========================================================================
@pytest.mark.parametrize("empty", ["", "   ", None, []])
def test_empty_cli_value_ignored(empty):
    scope = build({"preset": "urgent", "min_severity": empty, "lookback_days": empty})
    assert scope.min_severity == "HIGH"    # preset 값 유지
    assert scope.lookback_days == 1


def test_empty_preset_name_ignored():
    scope = build({"preset": ""})
    assert scope.preset is None
    assert scope.lookback_days == 3


def test_merge_layers_ignores_unknown_and_empty():
    merged = merge_layers({"lookback_days": 5, "존재하지않는키": 1},
                          {"min_severity": ""},
                          {"max_rows": 10, "min_severity": None})
    assert merged["lookback_days"] == 5
    assert merged["min_severity"] == "MEDIUM"   # 빈 값들이 무시되어 기본값 유지
    assert merged["max_rows"] == 10
    assert "존재하지않는키" not in merged


# ==========================================================================
#  3. sw_names 가 groups·only_in_use 를 이긴다
# ==========================================================================
def test_sw_names_beats_groups():
    scope = build({"sw_names": "PyTorch,vLLM", "groups": "ui"})
    assert scope.target_names == ["PyTorch", "vLLM"]   # groups=ui 는 무시됨


def test_sw_names_beats_only_in_use():
    scope = build({"sw_names": "TensorFlow", "only_in_use": True})
    assert scope.target_names == ["TensorFlow"]        # in_use=False 인데도 선택됨


def test_sw_names_matches_alias_case_insensitive():
    scope = build({"sw_names": "torch, VLLM"})
    assert scope.target_names == ["PyTorch", "vLLM"]


def test_sw_names_unmatched_recorded():
    scope = build({"sw_names": "PyTorch,없는SW"})
    assert scope.target_names == ["PyTorch"]
    assert scope.unmatched_sw == ["없는sw"]


def test_groups_filter():
    scope = build({"groups": "serving,ui"})
    assert scope.target_names == ["vLLM", "Ollama", "Gradio"]


def test_only_in_use_filter():
    scope = build({"only_in_use": True})
    assert scope.target_names == ["PyTorch", "vLLM", "Gradio"]


def test_groups_and_only_in_use_combined():
    scope = build({"groups": "serving", "only_in_use": True})
    assert scope.target_names == ["vLLM"]


def test_disabled_entry_always_excluded():
    """enabled: false 는 어떤 조건에서도 나오지 않는다."""
    assert "폐기예정SW" not in build({"groups": "ui"}).target_names
    assert "폐기예정SW" not in build({"only_in_use": True}).target_names
    assert "폐기예정SW" not in build({"sw_names": "폐기예정SW"}).target_names


def test_in_use_preset_applies_only_in_use():
    scope = build({"preset": "in_use"})
    assert scope.only_in_use is True
    assert scope.target_names == ["PyTorch", "vLLM", "Gradio"]


def test_select_targets_empty_result():
    chosen, unmatched = select_targets(WATCHLIST, [], ["vectordb"], False)
    assert chosen == []
    assert unmatched == []


# ==========================================================================
#  4. 기간 계산
# ==========================================================================
def test_lookback_date_range():
    scope = build({"lookback_days": 3})
    today = date(2026, 8, 14)
    start, end = scope.date_range(today=today)
    assert end == today
    assert start == date(2026, 8, 12)      # 오늘 포함 3일


def test_absolute_range_wins_over_lookback():
    scope = build({"lookback_days": 3, "date_from": "2026-07-01", "date_to": "2026-07-31"})
    start, end = scope.date_range()
    assert (start, end) == (date(2026, 7, 1), date(2026, 7, 31))
    assert scope.uses_absolute_range is True


def test_date_to_only_backfills_from():
    scope = build({"lookback_days": 5, "date_to": "2026-07-31"})
    start, end = scope.date_range()
    assert (start, end) == (date(2026, 7, 27), date(2026, 7, 31))


def test_date_from_only_uses_today_as_end():
    scope = build({"date_from": "2026-07-01"})
    start, end = scope.date_range(today=date(2026, 8, 14))
    assert start == date(2026, 7, 1)
    assert end == date(2026, 8, 14)


def test_backfill_preset():
    scope = build({"preset": "backfill"})
    assert scope.date_from == "2026-01-01"
    assert scope.excel_scope == "all"
    assert scope.max_rows == 5000


def test_various_date_formats_accepted():
    assert build({"date_from": "2026/07/01"}).date_from == "2026-07-01"
    assert build({"date_from": "20260701"}).date_from == "2026-07-01"


def test_reversed_range_rejected():
    with pytest.raises(ScopeError):
        build({"date_from": "2026-08-01", "date_to": "2026-07-01"})


# ==========================================================================
#  5. 심각도 필터 (KEV 는 항상 통과)
# ==========================================================================
def test_severity_filter():
    scope = build({"min_severity": "HIGH"})
    assert scope.severity_allowed("CRITICAL")
    assert scope.severity_allowed("HIGH")
    assert not scope.severity_allowed("MEDIUM")
    assert not scope.severity_allowed("LOW")


def test_kev_always_passes_severity_filter():
    scope = build({"min_severity": "CRITICAL"})
    assert not scope.severity_allowed("LOW")
    assert scope.severity_allowed("LOW", kev=True)     # KEV 등재 건은 무조건 포함
    assert scope.severity_allowed("NONE", kev=True)


def test_severity_all_passes_everything():
    scope = build({"min_severity": "ALL"})
    assert scope.severity_allowed("NONE")
    assert scope.min_severity_rank == -1


# ==========================================================================
#  6. 검증 오류
# ==========================================================================
@pytest.mark.parametrize("cli", [
    {"min_severity": "URGENT"},
    {"groups": "없는그룹"},
    {"sources": "nvd,mysource"},
    {"excel_scope": "partial"},
    {"max_rows": "많이"},
    {"max_rows": 0},
    {"lookback_days": 0},
    {"lookback_days": "사흘"},
    {"date_from": "2026-13-99"},
    {"preset": "없는프리셋"},
])
def test_invalid_values_rejected(cli):
    with pytest.raises(ScopeError):
        build(cli)


def test_severity_and_sources_normalized_to_upper_lower():
    scope = build({"min_severity": "high", "sources": "NVD, Osv", "groups": "Serving"})
    assert scope.min_severity == "HIGH"
    assert scope.sources == ["nvd", "osv"]
    assert scope.groups == ["serving"]


# ==========================================================================
#  7. SCOPE 한 줄 요약 (엑셀 META·메일·run_log 에 그대로 실린다)
# ==========================================================================
def test_scope_desc_format():
    scope = build({"preset": "urgent", "groups": "serving,ui",
                   "sources": "osv,kev", "max_rows": 300, "lookback_days": 3})
    assert scope.desc == (
        "SCOPE lookback=3 sev>=HIGH groups=serving,ui sw=- "
        "in_use=False src=osv,kev scope=delta max=300")


def test_scope_desc_with_absolute_range():
    scope = build({"date_from": "2026-01-01", "date_to": "2026-01-31"})
    assert scope.desc.startswith("SCOPE from=2026-01-01 to=2026-01-31 sev>=MEDIUM")


def test_scope_desc_with_sw_names():
    scope = build({"sw_names": "PyTorch,vLLM"})
    assert " sw=PyTorch,vLLM " in scope.desc


def test_scope_json_roundtrip():
    import json
    scope = build({"preset": "daily"})
    data = json.loads(scope.to_json())
    assert data["min_severity"] == "MEDIUM"
    assert data["target_count"] == 5
    assert "PyTorch" in data["target_names"]
    assert data["resolved_from"] <= data["resolved_to"]


def test_meta_items_keys_and_order():
    scope = build({"preset": "daily"})
    keys = [k for k, _ in scope.meta_items()]
    assert keys == ["SCOPE_DESC", "DATE_FROM", "DATE_TO", "MIN_SEVERITY", "GROUPS",
                    "SW_NAMES", "ONLY_IN_USE", "SOURCES", "EXCEL_SCOPE", "MAX_ROWS"]
    values = dict(scope.meta_items())
    assert len(values["DATE_FROM"]) == 8      # YYYYMMDD 문자열
    assert values["ONLY_IN_USE"] == "N"


# ==========================================================================
#  8. 실제 설정 파일이 규격을 지키는지
# ==========================================================================
def test_real_config_files_load():
    settings = load_settings("config/settings.yml")
    watchlist = load_watchlist("config/watchlist.yml")
    assert len(watchlist) >= 30, "감시 대상은 최소 30종이어야 한다"

    names = [w["canonical_name"] for w in watchlist]
    assert len(names) == len(set(names)), "canonical_name 중복"

    for preset in settings["presets"]:
        scope = resolve_scope(cli={"preset": preset}, settings=settings,
                              watchlist=watchlist)
        assert scope.desc.startswith("SCOPE ")
        assert len(scope.targets) > 0


def test_real_watchlist_covers_required_products():
    watchlist = load_watchlist("config/watchlist.yml")
    names = {w["canonical_name"] for w in watchlist}
    required = {
        "PyTorch", "TensorFlow", "JAX", "ONNX Runtime", "OpenVINO", "DeepSpeed",
        "Triton Inference Server", "vLLM", "Ollama", "llama.cpp",
        "Text Generation Inference", "LocalAI", "SGLang", "Transformers",
        "Hugging Face Hub", "Datasets", "Diffusers", "Tokenizers", "Accelerate",
        "PEFT", "LangChain", "LlamaIndex", "AutoGen", "CrewAI", "Haystack", "Dify",
        "n8n", "Gradio", "Streamlit", "Open WebUI", "ComfyUI",
        "AUTOMATIC1111 Stable Diffusion WebUI", "AnythingLLM", "ChromaDB", "Milvus",
        "Qdrant", "Weaviate", "FAISS", "pgvector", "Elasticsearch", "MLflow", "Ray",
        "Kubeflow", "JupyterLab", "Jupyter Notebook", "Airflow", "DVC",
        "Label Studio", "NumPy", "Pandas", "Pillow", "protobuf", "gRPC", "FastAPI",
        "Uvicorn",
    }
    assert required <= names, f"누락된 감시 대상: {sorted(required - names)}"
