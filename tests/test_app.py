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


# --- Review finding HIGH-4: every client must see the whole stream ---


async def _collect(run_id, limit=10):
    """Drain the SSE generator the way a browser would."""
    out = []
    async for evt in app_module._subscribe(run_id):
        out.append(evt)
        if evt["event"] == "done" or len(out) >= limit:
            break
    return out


async def test_two_clients_on_one_run_each_receive_every_event():
    """A laptop and a projector on the same run. Previously each got alternating
    halves, because all clients shared one queue and get() is destructive."""
    import asyncio

    run = app_module._new_run("r1", ["vuln-demo"])
    a = asyncio.create_task(_collect("r1"))
    b = asyncio.create_task(_collect("r1"))
    await asyncio.sleep(0)  # let both subscribe

    for i in range(3):
        app_module._publish(run, {"node": "assess", "message": f"msg{i}"})
    app_module._finish(run)

    got_a, got_b = await a, await b
    msgs_a = [e["data"] for e in got_a if e["event"] == "step"]
    msgs_b = [e["data"] for e in got_b if e["event"] == "step"]

    assert msgs_a == msgs_b, "clients received different halves of the stream"
    assert len(msgs_a) == 3
    assert got_a[-1]["event"] == "done" and got_b[-1]["event"] == "done", "a client never got the done sentinel"


async def test_client_connecting_late_still_gets_earlier_events():
    """POST /scan starts the graph immediately; the browser subscribes a moment later.
    Without replay, everything emitted in that gap is lost."""
    run = app_module._new_run("r2", ["vuln-demo"])
    app_module._publish(run, {"node": "ingest", "message": "22 findings"})
    app_module._publish(run, {"node": "gather_context", "message": "probed 2"})
    app_module._finish(run)

    got = await _collect("r2")
    msgs = [e["data"] for e in got if e["event"] == "step"]
    assert len(msgs) == 2, "late subscriber lost the events emitted before it connected"
    assert got[-1]["event"] == "done"


async def test_finished_run_is_evicted_eventually():
    """Review finding MEDIUM-12: RUNS never shrank. A closed tab leaked a run forever."""
    for i in range(app_module.MAX_RUNS + 3):
        app_module._new_run(f"leak{i}", ["ns"])
    assert len(app_module.RUNS) <= app_module.MAX_RUNS


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
