"""Trivy misconfiguration scanning.

Trivy is the scanner. We do not write our own checks — see todo/kubesentinel.md.
The findings Trivy returns are NOT the product; they are the raw material. Every
finding here is graded on one resource in isolation, which is exactly the problem
KubeSentinel exists to fix.

`run_trivy` is the seam: tests patch it, nothing else in this module touches the world.
"""

import json
import logging
import subprocess
from dataclasses import asdict, dataclass

log = logging.getLogger("kubesentinel.scanner")

TRIVY_TIMEOUT_SECONDS = 120


class ScannerError(RuntimeError):
    """The scan did not run. Distinct from "the scan ran and found nothing".

    This distinction is the entire point of the exception. An earlier version caught
    every Trivy failure and returned an empty list, which the UI rendered as
    "No workloads assessed" - byte-identical to a clean cluster. A security tool that
    reports "clean" when it actually crashed is worse than one that reports nothing.
    Fail closed; let the caller say so out loud.
    """


@dataclass
class Finding:
    """One Trivy misconfiguration, as it applies to one resource."""

    id: str  # e.g. KSV-0017
    title: str
    severity: str  # Trivy's STATIC severity - the thing we re-rank
    message: str
    resolution: str
    namespace: str
    kind: str
    name: str

    def as_dict(self) -> dict:
        return asdict(self)


# --- Trivy invocation (the seam) ---


def run_trivy(namespaces: list[str]) -> dict:
    """Run a misconfiguration scan and return Trivy's raw JSON.

    Deliberately `--scanners misconfig`: it uses bundled Rego policies and needs no
    vulnerability DB download, which keeps a scan at ~5s instead of minutes.
    """
    cmd = [
        "trivy", "k8s",
        "--scanners", "misconfig",
        "--format", "json",
        "--report", "all",
        "--quiet",
    ]
    for ns in namespaces:
        cmd += ["--include-namespaces", ns]

    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=TRIVY_TIMEOUT_SECONDS
    )
    if proc.returncode != 0:
        raise ScannerError(f"trivy exited {proc.returncode}: {proc.stderr.strip()[:300]}")
    return json.loads(proc.stdout)


# --- Parsing ---


def parse_findings(raw: dict) -> list[Finding]:
    """Flatten Trivy's nested JSON into a list of Findings.

    Trivy nests: Resources[] -> Results[] -> Misconfigurations[]. Anything that does
    not match that shape is skipped rather than raised - a scanner quirk must never
    take the graph down.
    """
    findings: list[Finding] = []
    for resource in raw.get("Resources") or []:
        for result in resource.get("Results") or []:
            for m in result.get("Misconfigurations") or []:
                findings.append(
                    Finding(
                        id=m.get("ID", ""),
                        title=m.get("Title", ""),
                        severity=m.get("Severity", "UNKNOWN"),
                        message=m.get("Message", ""),
                        resolution=m.get("Resolution", ""),
                        namespace=resource.get("Namespace", ""),
                        kind=resource.get("Kind", ""),
                        name=resource.get("Name", ""),
                    )
                )
    return findings


def group_by_workload(findings: list[Finding]) -> dict[tuple[str, str, str], list[Finding]]:
    """Group findings by (namespace, kind, name).

    Blast radius is a property of a workload, not of a finding, so the agent reasons
    per workload with all of that workload's findings in view at once.
    """
    grouped: dict[tuple[str, str, str], list[Finding]] = {}
    for f in findings:
        grouped.setdefault((f.namespace, f.kind, f.name), []).append(f)
    return grouped


def scan(namespaces: list[str]) -> list[Finding]:
    """Scan and parse.

    Raises ScannerError if the scan could not run. Returns [] only when the scan ran
    and genuinely found nothing - those two outcomes must never look the same.
    """
    try:
        raw = run_trivy(namespaces)
    except ScannerError:
        raise
    except Exception as e:
        log.error("trivy scan failed: %s", e)
        raise ScannerError(f"trivy scan failed: {e}") from e
    return parse_findings(raw)
