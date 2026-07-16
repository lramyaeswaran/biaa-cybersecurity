"""KubeSentinel web layer.

    GET  /                    dashboard
    POST /scan                start a run, return the SSE hookup
    GET  /runs/{id}/events    live node transitions while the graph runs
    GET  /runs/{id}/report    the finished ranking

The SSE stream exists because the interesting part of an agent is the part you
normally cannot see. Streaming `stream_mode="updates"` puts every node transition on
screen as it happens, so a workshop audience watches the graph think instead of
staring at a spinner.

Runs live in memory. This is a single-replica demo tool, not a service.
"""

import asyncio
import logging
import os
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sse_starlette.sse import EventSourceResponse

from agents import build_graph
from llm import describe_provider

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("kubesentinel.app")

DEFAULT_NAMESPACES = os.getenv("SCAN_NAMESPACES", "vuln-demo,safe-demo")

# run_id -> {namespaces, queue, done, assessments, report, error}
RUNS: dict[str, dict] = {}

GRAPH = build_graph()


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("KubeSentinel starting — provider: %s", describe_provider())
    yield


app = FastAPI(title="KubeSentinel", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


# --- Dashboard ---


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(
        request,
        "index.html",
        {"provider": describe_provider(), "default_namespaces": DEFAULT_NAMESPACES},
    )


@app.get("/health", response_class=JSONResponse)
async def health():
    return {"status": "ok", "service": "kubesentinel"}


# --- Scanning ---


@app.post("/scan", response_class=HTMLResponse)
async def start_scan(request: Request, namespaces: str = Form(...)):
    ns_list = [n.strip() for n in namespaces.split(",") if n.strip()]
    run_id = uuid.uuid4().hex[:12]
    RUNS[run_id] = {
        "namespaces": ns_list,
        "queue": asyncio.Queue(),
        "done": False,
        "assessments": [],
        "report": "",
        "error": "",
    }
    asyncio.create_task(_execute_scan(run_id, ns_list))
    return templates.TemplateResponse(request, "_run.html", {"run_id": run_id, "namespaces": ns_list})


async def _execute_scan(run_id: str, namespaces: list[str]) -> None:
    """Drive the graph, pushing each node transition onto the run's queue."""
    run = RUNS[run_id]
    queue: asyncio.Queue = run["queue"]
    compiled = GRAPH.compile()
    initial = {
        "namespaces": namespaces,
        "findings": [], "workloads": [], "context": {},
        "probe_requests": [], "probe_rounds": 0,
        "assessments": [], "report": "", "error": "", "audit": [],
    }
    try:
        async for chunk in compiled.astream(initial, stream_mode="updates"):
            for node, update in chunk.items():
                for line in (update.get("audit") or []):
                    await queue.put({"node": node, "message": line})
                if update.get("assessments"):
                    run["assessments"] = update["assessments"]
                if update.get("report"):
                    run["report"] = update["report"]
                if update.get("error"):
                    run["error"] = update["error"]
    except Exception as e:
        log.exception("scan %s failed", run_id)
        run["error"] = str(e)
        await queue.put({"node": "error", "message": str(e)})
    finally:
        run["done"] = True
        await queue.put(None)  # sentinel: stream complete


@app.get("/runs/{run_id}/events")
async def events(run_id: str):
    run = RUNS.get(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="unknown run")

    async def stream():
        queue: asyncio.Queue = run["queue"]
        while True:
            item = await queue.get()
            if item is None:
                yield {"event": "done", "data": run_id}
                return
            yield {"event": "step", "data": f"{item['node']}|{item['message']}"}

    return EventSourceResponse(stream())


@app.get("/runs/{run_id}/report", response_class=HTMLResponse)
async def run_report(request: Request, run_id: str):
    run = RUNS.get(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="unknown run")
    return templates.TemplateResponse(
        request,
        "_report.html",
        {"assessments": run["assessments"], "error": run["error"], "run_id": run_id},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
