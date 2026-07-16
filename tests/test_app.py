"""Web layer tests. The graph is mocked — these test the HTTP surface, not the agent."""

from unittest.mock import MagicMock, patch

import httpx
import pytest

import app as app_module
from app import app


@pytest.fixture
def client():
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


@pytest.fixture(autouse=True)
def clear_runs():
    app_module.RUNS.clear()
    yield
    app_module.RUNS.clear()


async def test_dashboard_renders(client):
    r = await client.get("/")
    assert r.status_code == 200
    assert "KubeSentinel" in r.text


async def test_dashboard_shows_active_provider(client):
    with patch.object(app_module, "describe_provider", return_value="Groq / openai/gpt-oss-120b"):
        r = await client.get("/")
    assert "openai/gpt-oss-120b" in r.text


async def test_health(client):
    r = await client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "service": "kubesentinel"}


async def test_scan_starts_a_run_and_returns_its_id(client):
    with patch.object(app_module, "_execute_scan", return_value=None):
        r = await client.post("/scan", data={"namespaces": "vuln-demo,safe-demo"})
    assert r.status_code == 200
    assert len(app_module.RUNS) == 1
    run_id = next(iter(app_module.RUNS))
    assert run_id in r.text  # the SSE hookup is wired to this run


async def test_scan_parses_comma_separated_namespaces(client):
    captured = {}

    async def fake(run_id, namespaces):
        captured["ns"] = namespaces

    with patch.object(app_module, "_execute_scan", side_effect=fake):
        await client.post("/scan", data={"namespaces": " vuln-demo , safe-demo "})
    run = next(iter(app_module.RUNS.values()))
    assert run["namespaces"] == ["vuln-demo", "safe-demo"]


async def test_events_for_unknown_run_is_404(client):
    r = await client.get("/runs/does-not-exist/events")
    assert r.status_code == 404


async def test_report_for_unknown_run_is_404(client):
    r = await client.get("/runs/does-not-exist/report")
    assert r.status_code == 404


async def test_report_renders_finished_run(client):
    app_module.RUNS["abc"] = {
        "namespaces": ["vuln-demo"],
        "queue": None,
        "done": True,
        "assessments": [
            {
                "workload": "vuln-demo/payments-api",
                "severity": "CRITICAL",
                "blast_radius": "full cluster takeover",
                "cited_facts": ["cluster-admin SA", "cloud-credentials mounted"],
                "rationale": "compounding",
                "remediation": "drop privileged",
            }
        ],
        "error": "",
    }
    r = await client.get("/runs/abc/report")
    assert r.status_code == 200
    assert "CRITICAL" in r.text
    assert "payments-api" in r.text
    assert "cluster-admin SA" in r.text


async def test_report_escapes_untrusted_workload_names(client):
    """Injection guard: resource names are attacker-controlled and must never render as HTML."""
    app_module.RUNS["xss"] = {
        "namespaces": ["vuln-demo"],
        "queue": None,
        "done": True,
        "assessments": [
            {
                "workload": "<script>alert(1)</script>",
                "severity": "LOW",
                "blast_radius": "x",
                "cited_facts": ["<img src=x onerror=alert(2)>"],
                "rationale": "r",
                "remediation": "m",
            }
        ],
        "error": "",
    }
    r = await client.get("/runs/xss/report")
    assert "<script>alert(1)</script>" not in r.text
    assert "&lt;script&gt;" in r.text
