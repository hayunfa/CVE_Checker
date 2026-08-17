"""NVD keywordSearch 결과가 정말 그 제품 건인지 판정하는 로직 검증.

NVD 는 설명에 제품명이 스치기만 해도 물어온다.
그래서 CyberPanel 취약점이 FastAPI 에, etcd 취약점이 gRPC 에 붙는 오매칭이 생겼다.
반대로 너무 빡세게 걸면 진짜 취약점을 놓치므로 양쪽을 모두 테스트한다.
"""
from __future__ import annotations

import pytest

from src.aicve.sources.nvd import _is_relevant, _is_subject

# ---- 테스트용 watchlist 항목 ----
FASTAPI = {"canonical_name": "FastAPI", "cpe_keyword": "fastapi",
           "aliases": ["fastapi", "tiangolo/fastapi"], "pypi": "fastapi"}
GRPC = {"canonical_name": "gRPC", "cpe_keyword": "grpc",
        "aliases": ["grpcio", "grpc"], "pypi": "grpcio"}
ELASTIC = {"canonical_name": "Elasticsearch", "cpe_keyword": "elasticsearch",
           "aliases": ["elasticsearch", "elasticsearch-py"], "pypi": "elasticsearch"}
VLLM = {"canonical_name": "vLLM", "cpe_keyword": "vllm",
        "aliases": ["vllm"], "pypi": "vllm"}
AIRFLOW = {"canonical_name": "Airflow", "cpe_keyword": "apache airflow",
           "aliases": ["apache-airflow", "airflow"], "pypi": "apache-airflow"}
JUPYTERLAB = {"canonical_name": "JupyterLab", "cpe_keyword": "jupyterlab",
              "aliases": ["jupyterlab"], "pypi": "jupyterlab"}
NOTEBOOK = {"canonical_name": "Jupyter Notebook", "cpe_keyword": "jupyter notebook",
            "aliases": ["notebook", "jupyter notebook"], "pypi": "notebook"}
PANDAS = {"canonical_name": "Pandas", "cpe_keyword": "pandas",
          "aliases": ["pandas"], "pypi": "pandas"}
STREAMLIT = {"canonical_name": "Streamlit", "cpe_keyword": "streamlit",
             "aliases": ["streamlit"], "pypi": "streamlit"}


# ==========================================================================
#  실제로 잘못 붙었던 건들 — 반드시 걸러야 한다
# ==========================================================================
WRONG = [
    (FASTAPI, "CyberPanel before 3.0.0 contains a hard-coded JWT secret vulnerability "
              "in the WebTerminal FastAPI SSH service that allows unauthenticated "
              "remote attackers to forge valid tokens."),
    (FASTAPI, "vLLM is an inference and serving engine for large language models. "
              "Prior to 0.26.0, the validation_exception_handler in "
              "vllm/entrypoints/openai/server_utils.py converts FastAPI "
              "RequestValidationError objects with repr()."),
    (FASTAPI, "Apache Airflow's Backfill API authorized a request against a Dag id "
              "supplied by the caller while the FastAPI route resolved another."),
    (GRPC, "etcd is a distributed key-value store for the data of a distributed "
           "system. Prior to versions 3.5.33, a user with permission on a single "
           "exact key can use the Watch gRPC API with clientv3.WithFromKey()."),
    (GRPC, "SeaweedFS is a distributed storage system. Prior to 4.24, "
           "VolumeServer.FetchAndWriteNeedle in weed/server/volume_grpc_remote.go "
           "fetches a caller-supplied URL."),
    (GRPC, "A vulnerability has been found in SpaceX Starlink Router Gen 3 "
           "2025.11.14.mr64708.3. This affects the function get_status of the "
           "component gRPC Management Interface."),
    (GRPC, "The dataplane token validator in kuma-cp performs an unchecked Go type "
           "assertion on the gRPC metadata supplied by the caller."),
    (PANDAS, "Flowise before 3.1.3 contains a regex-based Python code validator "
             "bypass in CSV and Airtable Agent nodes. Attackers can exploit "
             "unblocked pandas functions like pd.read_json() to execute code."),
    (NOTEBOOK, "jupyterlab is an extensible environment for interactive and "
               "reproducible computing, based on the Jupyter Notebook Architecture. "
               "Prior to 4.5.10 and 4.6.2, the image viewer allows XSS."),
    (STREAMLIT, "Insufficient input sanitization in Snowflake Python API "
                "(`snowflake.core`) versions before 1.9.0 allows an attacker to "
                "inject SQL through a Streamlit app parameter."),
    (ELASTIC, "Observable Discrepancy (CWE-203) in Kibana Fleet can lead to "
              "information disclosure via Excavation (CAPEC-116). Fleet removes "
              "the Elasticsearch API key when an integration is deleted."),
    (ELASTIC, "Missing Authorization (CWE-862) in Kibana can lead to cross-space "
              "information disclosure and unauthorized data modification."),
    (ELASTIC, "Insecure direct object reference in the mongodb_memory, "
              "elasticsearch_memory, and mem0_memory tools in Amazon Strands "
              "Agents Tools before 0.8.3 might allow access to other sessions."),
]


@pytest.mark.parametrize("target, description", WRONG,
                         ids=[f"{t['canonical_name']}-{i}"
                              for i, (t, _) in enumerate(WRONG)])
def test_other_products_advisory_is_rejected(target, description):
    assert not _is_subject(description, target), (
        f"{target['canonical_name']} 건이 아닌데 채택됐다")


# ==========================================================================
#  진짜 그 제품 건 — 절대 놓치면 안 된다
# ==========================================================================
RIGHT = [
    (VLLM, "vLLM is an inference and serving engine for large language models. "
           "From 0.19.0 until 0.26.0, the /v1/completions field accepts input."),
    (AIRFLOW, "Apache Airflow's serialization layer reconstructed exception nodes "
              "by importing arbitrary modules."),
    (JUPYTERLAB, "JupyterLab's image viewer allows for cross-site scripting (XSS) "
                 "when a specially-crafted image file is opened."),
    (FASTAPI, "FastAPI before 0.109.1 is vulnerable to a denial of service via "
              "a crafted multipart form."),
    (PANDAS, "pandas 2.1.0 allows arbitrary code execution via read_pickle()."),
    # CWE 번호가 앞에 붙어 제품명이 뒤로 밀리는 Elastic 계열 권고문
    (ELASTIC, "Uncontrolled Recursion (CWE-674) in Elasticsearch can lead to "
              "denial of service via Input Data Manipulation (CAPEC-153)."),
    (ELASTIC, "Memory Allocation with Excessive Size Value (CWE-789) in the ES|QL "
              "query processing of Elasticsearch can lead to denial of service."),
    (ELASTIC, "Elasticsearch does not enforce an upper bound on a user-supplied "
              "count accepted by a search highlighting option."),
    (ELASTIC, "A flaw in Elasticsearch allows a low-privileged authenticated user "
              "to submit a single small request containing a crafted input."),
    (ELASTIC, "Uncontrolled Recursion (CWE-674) in the Elasticsearch wildcard "
              "matching helper can lead to a denial of service."),
    (ELASTIC, "The native inference process that Elasticsearch uses to evaluate "
              "uploaded machine learning models accepts a model operation."),
]


@pytest.mark.parametrize("target, description", RIGHT,
                         ids=[f"{t['canonical_name']}-{i}"
                              for i, (t, _) in enumerate(RIGHT)])
def test_real_advisory_is_kept(target, description):
    assert _is_subject(description, target), (
        f"{target['canonical_name']} 진짜 건인데 걸러졌다 — 취약점을 놓친다")


def test_identifier_substring_is_not_a_mention():
    """'elasticsearch_memory' 는 Elasticsearch 언급이 아니다."""
    assert not _is_subject("A bug in elasticsearch_memory tool at position x.", ELASTIC)
    assert not _is_subject("The myfastapi_helper module is affected.", FASTAPI)


def test_empty_description():
    assert not _is_subject("", VLLM)
    assert not _is_subject(None, VLLM)


# ==========================================================================
#  CPE 기반 판정 (_is_relevant 전체 흐름)
# ==========================================================================
def cve_with(cpes=None, description=""):
    return {
        "descriptions": [{"lang": "en", "value": description}],
        "configurations": ([{"nodes": [{"cpeMatch": [
            {"criteria": c, "vulnerable": True} for c in cpes]}]}] if cpes else []),
    }


def test_matching_cpe_is_accepted():
    cve = cve_with(["cpe:2.3:a:vllm:vllm:*:*:*:*:*:*:*:*"], "무관한 설명")
    ok, reason = _is_relevant(cve, VLLM, {"vllm"})
    assert ok and reason == "cpe"


def test_cpe_for_another_product_is_rejected():
    """NVD 가 CPE 를 붙였는데 다른 제품이면 그 제품 건이 아니다.

    실제 사례: CVE-2026-45799 는 CPE 가 squareup:wire 뿐인데
    설명에 gRPC/protobuf 가 언급돼 잘못 들어왔다.
    """
    cve = cve_with(["cpe:2.3:a:squareup:wire:*:*:*:*:*:*:*:*"],
                   "Wire provides gRPC and protocol buffers for Android.")
    ok, reason = _is_relevant(cve, GRPC, {"grpc", "grpcio"})
    assert not ok and reason == "cpe-mismatch"


def test_no_cpe_falls_back_to_subject_test():
    """CPE 가 아직 없는 신규 CVE 는 설명의 주어로 판정한다."""
    cve = cve_with([], "vLLM is an inference engine. From 0.19.0 until 0.26.0 ...")
    ok, reason = _is_relevant(cve, VLLM, {"vllm"})
    assert ok and reason == "subject"

    cve = cve_with([], "CyberPanel before 3.0.0 uses the WebTerminal FastAPI service.")
    ok, reason = _is_relevant(cve, FASTAPI, {"fastapi"})
    assert not ok and reason == "mention-only"
