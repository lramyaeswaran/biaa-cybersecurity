"""Scanner parsing tests. Trivy itself is never executed here — run_trivy() is the seam."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

import scanner

FIXTURE = Path(__file__).parent / "fixtures" / "trivy-vuln-demo.json"


@pytest.fixture
def raw_trivy():
    return json.loads(FIXTURE.read_text())


# --- Parsing ---


def test_parses_real_trivy_output_into_findings(raw_trivy):
    findings = scanner.parse_findings(raw_trivy)
    # The fixture is a real scan of vuln-demo/payments-api: 19 misconfigurations.
    assert len(findings) == 19


def test_finding_carries_the_fields_the_agent_reasons_over(raw_trivy):
    findings = scanner.parse_findings(raw_trivy)
    privileged = next(f for f in findings if f.id == "KSV-0017")
    assert privileged.severity == "HIGH"
    assert privileged.namespace == "vuln-demo"
    assert privileged.kind == "Deployment"
    assert privileged.name == "payments-api"
    assert "Privileged" in privileged.title
    assert privileged.resolution  # non-empty: we surface the scanner's own fix hint


def test_findings_group_by_workload(raw_trivy):
    findings = scanner.parse_findings(raw_trivy)
    grouped = scanner.group_by_workload(findings)
    assert list(grouped) == [("vuln-demo", "Deployment", "payments-api")]
    assert len(grouped[("vuln-demo", "Deployment", "payments-api")]) == 19


# --- Robustness: a scanner failure must not kill the graph ---


def test_malformed_json_yields_no_findings_not_an_exception():
    assert scanner.parse_findings({"nonsense": True}) == []


def test_resource_with_no_results_is_skipped():
    assert scanner.parse_findings({"Resources": [{"Kind": "ConfigMap", "Results": None}]}) == []


def test_scan_raises_rather_than_failing_open(caplog):
    """Review finding HIGH-3.

    This test previously asserted the OPPOSITE — that a Trivy failure yields []. That
    was wrong, and dangerously so: an empty list is indistinguishable from a clean
    cluster, so a crashed scanner rendered as a green result. For a security tool that
    is the worst available failure mode. Fail closed and let the caller say so.
    """
    with patch.object(scanner, "run_trivy", side_effect=RuntimeError("trivy exploded")):
        with pytest.raises(scanner.ScannerError, match="trivy exploded"):
            scanner.scan(["vuln-demo"])


def test_scan_returns_findings_on_success(raw_trivy):
    with patch.object(scanner, "run_trivy", return_value=raw_trivy):
        assert len(scanner.scan(["vuln-demo"])) == 19


def test_clean_scan_returns_empty_list_without_raising():
    """A genuinely clean namespace is not an error - it must stay distinguishable."""
    with patch.object(scanner, "run_trivy", return_value={"Resources": []}):
        assert scanner.scan(["empty-ns"]) == []
