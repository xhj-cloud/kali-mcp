"""Tests for the system_patch_audit tool (vuls-based patch audit).

Pure-logic tests: the executor is replaced with a fake that records
calls and writes simulated vuls result files, so no vuls binary, SSH
target or network access is needed.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile

import pytest

from kali_mcp.executor import CommandResult
import kali_mcp.vulnscan as vulnscan
from kali_mcp.vulnscan import (
    SystemPatchAuditInput,
    _extract_cve_fields,
    _severity_from_score,
    _strip_html,
    _toml_escape,
    system_patch_audit,
)


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeExecutor:
    """Executor stub: matches commands by predicate, returns canned
    results and records every call (cmd + env)."""

    def __init__(self, handlers: list[tuple[callable, CommandResult]]):
        self.handlers = handlers
        self.calls: list[tuple[list[str], dict | None]] = []

    async def run(self, cmd, timeout=None, input_data=None, hold_stdin=False,
                  env=None):
        self.calls.append((list(cmd), env))
        for predicate, result in self.handlers:
            if predicate(cmd):
                if callable(result):
                    return result(cmd)
                return result
        return CommandResult(
            stdout="",
            stderr="no fake handler for: " + " ".join(cmd),
            returncode=1,
            success=False,
        )


def _ok(stdout: str = "", stderr: str = "") -> CommandResult:
    return CommandResult(stdout=stdout, stderr=stderr,
                         returncode=0, success=True)


def _err(stderr: str) -> CommandResult:
    return CommandResult(stdout="", stderr=stderr, returncode=1,
                         success=False)


def _audit(params: SystemPatchAuditInput) -> str:
    return asyncio.run(system_patch_audit(params))


def _windows_cves() -> dict:
    """Realistic vuls2-reported scannedCves (subset, Windows shape)."""
    return {
        "CVE-2024-21413": {
            "cveID": "CVE-2024-21413",
            "confidences": [{"score": 100,
                             "detectionMethod": "WindowsUpdateSearch"}],
            "affectedPackages": [
                {
                    "name": "Windows 11 Version 23H2 for x64-based Systems",
                    "fixedIn": "10.0.22631.3880",
                }
            ],
            "cveContents": {
                "microsoft": [
                    {
                        "type": "microsoft",
                        "cveID": "CVE-2024-21413",
                        "title": "Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability",
                        "summary": "",
                        "cvss2Score": 0,
                        "cvss3Score": 8.4,
                        "cvss3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                        "cvss3Severity": "HIGH",
                        "cvss40Score": 0,
                        "sourceLink": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413",
                        "references": [
                            {
                                "link": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413",
                                "source": "MISC",
                            }
                        ],
                    }
                ]
            },
        },
        "CVE-2023-21768": {
            "cveID": "CVE-2023-21768",
            "affectedPackages": [
                {
                    "name": "Windows 11 Version 23H2 for x64-based Systems",
                    "fixedIn": "10.0.22631.1847",
                }
            ],
            "cveContents": {
                "microsoft": [
                    {
                        "cveID": "CVE-2023-21768",
                        "title": "Windows Scripting Engine Memory Corruption Vulnerability",
                        "summary": "",
                        "cvss3Score": 8.8,
                        "cvss3Severity": "HIGH",
                        "sourceLink": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21768",
                        "references": [],
                    }
                ]
            },
            "distroAdvisories": [
                {
                    "advisoryID": "CVE-2023-21768",
                    "severity": "High",
                    "description": (
                        "<p><strong>Executive Summary:</strong></p>"
                        "<p>A memory corruption vulnerability exists in "
                        "Windows Scripting Engine.</p>"
                    ),
                }
            ],
        },
        "ADV20240001": {
            "cveID": "ADV20240001",
            "distroAdvisories": [
                {"advisoryID": "ADV20240001", "severity": "None",
                 "description": "Advisory without CVSS."}
            ],
        },
    }


# ---------------------------------------------------------------------------
# Unit tests: pure helpers
# ---------------------------------------------------------------------------


def test_extract_cve_fields_vuls2_shape():
    cve = _windows_cves()["CVE-2024-21413"]
    score, title, desc, links = _extract_cve_fields(cve)
    assert score == 8.4
    assert title.startswith("Windows Ancillary Function Driver")
    assert desc == ""
    assert links == [
        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413"
    ]


def test_extract_cve_fields_html_fallback_description():
    cve = _windows_cves()["CVE-2023-21768"]
    score, title, desc, links = _extract_cve_fields(cve)
    assert score == 8.8
    assert "Windows Scripting Engine Memory Corruption" in title
    # HTML stripped from distroAdvisories description
    assert "<" not in desc
    assert "memory corruption vulnerability exists" in desc
    assert links == [
        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21768"
    ]


def test_extract_cve_fields_no_score_is_unknown():
    cve = _windows_cves()["ADV20240001"]
    score, title, desc, links = _extract_cve_fields(cve)
    assert score is None
    assert _severity_from_score(score) == "unknown"


def test_strip_html():
    assert _strip_html("<p><strong>A</strong> B</p>\n\nC") == "A B C"


def test_severity_bands():
    assert _severity_from_score(9.8) == "critical"
    assert _severity_from_score(9.0) == "critical"
    assert _severity_from_score(7.0) == "high"
    assert _severity_from_score(4.0) == "medium"
    assert _severity_from_score(0.1) == "low"
    assert _severity_from_score(0) == "unknown"
    assert _severity_from_score(None) == "unknown"


def test_toml_escape():
    assert _toml_escape('a"b\\c') == 'a\\"b\\\\c'


# ---------------------------------------------------------------------------
# Integration-style tests with a fake executor
# ---------------------------------------------------------------------------


@pytest.fixture
def shim_dir(tmp_path, monkeypatch):
    d = tmp_path / "shim"
    d.mkdir()
    (d / "ssh").write_text("#!/bin/sh\nexit 0\n")
    (d / "ssh").chmod(0o755)
    monkeypatch.setenv(vulnscan.VULS_SSH_SHIM_DIR_ENV, str(d))
    return d


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    wd = tmp_path / "vuls-audit-test"
    wd.mkdir()
    monkeypatch.setattr(tempfile, "mkdtemp", lambda prefix="": str(wd))
    return wd


def _write_scan_result(workdir, data: dict) -> None:
    results = workdir / "results" / "2026-09-01T18-00-00+0800"
    results.mkdir(parents=True, exist_ok=True)
    (results / "audit-target.json").write_text(
        json.dumps(data), encoding="utf-8"
    )


def _base_scan(family: str, **extra) -> dict:
    base = {
        "serverName": "audit-target",
        "family": family,
        "release": extra.pop("release", ""),
        "errors": [],
        "scannedCves": {},
        "packages": {},
        "runningKernel": {"release": "10.0", "version": "10.0",
                          "rebootRequired": False},
    }
    base.update(extra)
    return base


def test_success_windows_report(tmp_path, workdir, shim_dir, monkeypatch):
    monkeypatch.setenv(vulnscan.VULS2_DB_PATH_ENV, str(tmp_path / "vuls.db"))
    _write_scan_result(workdir, _base_scan(
        "windows",
        release="Windows 11 Version 23H2 for x64-based Systems",
        windowsKB={"applied": ["5054156", "5056579"],
                   "unapplied": ["5058405"]},
        runningKernel={"release": "10.0.22631.3880",
                       "version": "10.0.22631.3880",
                       "rebootRequired": False},
    ))

    captured: dict = {}

    def report_side_effect(cmd):
        # Simulate vuls report writing the correlation back into the
        # scan result JSON (v0.39.x in-place behavior).
        for f in (workdir / "results").glob("*/*.json"):
            data = json.loads(f.read_text(encoding="utf-8"))
            data["scannedCves"] = _windows_cves()
            f.write_text(json.dumps(data), encoding="utf-8")
        captured["config"] = (workdir / "config.toml").read_text(
            encoding="utf-8"
        )
        captured["known_hosts"] = (workdir / "known_hosts").read_text(
            encoding="utf-8"
        )
        return _ok(stderr="audit-target: 3 CVEs are detected with vuls2")

    exec_ = FakeExecutor([
        (lambda c: c[0].endswith("ssh-keyscan"),
         _ok(stdout="[100.101.5.100]:22 ssh-ed25519 AAAATESTKEY")),
        (lambda c: len(c) > 1 and c[1] == "scan", _ok(stderr="scan done")),
        (lambda c: len(c) > 1 and c[1] == "report",
         lambda c: report_side_effect(c)),
    ])
    monkeypatch.setattr(vulnscan, "get_executor",
                        lambda timeout=30: exec_)

    out = _audit(SystemPatchAuditInput(host="100.101.5.100",
                                       user="Administrator"))

    # Report rendered with real vuls2 fields
    assert "系统补丁审计报告" in out
    assert "CVE-2024-21413" in out
    assert "CVSS: 8.4" in out
    assert "→ 10.0.22631.3880" in out
    assert "msrc.microsoft.com" in out
    # Windows KB sections
    assert "个已应用" in out
    assert "KB5058405" in out
    # Unscored ADV lands in the unknown bucket
    assert "ADV20240001" in out
    # HTML description stripped
    assert "<p>" not in out
    # Config written with persistent vuls2 DB path (captured before the
    # success cleanup removed the workdir).
    cfg = captured["config"]
    assert "[vuls2]" in cfg
    assert str(tmp_path / "vuls.db") in cfg
    assert "[servers]" in cfg
    # Known hosts populated from keyscan
    assert captured["known_hosts"].startswith("[100.101.5.100]")
    # Workdir cleaned up on success (fake mkdtemp dir removed)
    assert not os.path.isdir(str(workdir))


def test_password_via_env_never_argv(tmp_path, workdir, shim_dir, monkeypatch):
    monkeypatch.setenv(vulnscan.VULS2_DB_PATH_ENV, str(tmp_path / "vuls.db"))
    _write_scan_result(workdir, _base_scan(
        "windows",
        release="Windows 10 Version 22H2 for x64-based Systems",
    ))
    exec_ = FakeExecutor([
        (lambda c: c[0].endswith("ssh-keyscan"), _ok(stdout="x ssh-rsa k")),
        (lambda c: len(c) > 1 and c[1] == "scan", _ok()),
        (lambda c: len(c) > 1 and c[1] == "report",
         _ok(stderr="audit-target: 0 CVEs are detected with vuls2")),
    ])
    monkeypatch.setattr(vulnscan, "get_executor", lambda timeout=30: exec_)

    out = _audit(SystemPatchAuditInput(
        host="10.0.0.5", user="Administrator", password="s3cret-pw"
    ))
    assert "未发现未修复的已知 CVE" in out

    # The password must travel via env only, never argv.
    vuls_calls = [(c, e) for c, e in exec_.calls
                  if len(c) > 1 and c[1] in ("scan", "report")]
    assert vuls_calls
    for cmd, env in vuls_calls:
        assert "s3cret-pw" not in " ".join(cmd), "password leaked into argv"
    scan_call = next((c, e) for c, e in vuls_calls if c[1] == "scan")
    assert scan_call[1] is not None
    assert scan_call[1].get("VULS_SSH_PASSWORD") == "s3cret-pw"
    # PATH shim prepended
    assert scan_call[1]["PATH"].startswith(str(shim_dir))


def test_password_without_shim_fails_fast(tmp_path, monkeypatch):
    monkeypatch.delenv(vulnscan.VULS_SSH_SHIM_DIR_ENV, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))  # default shim dir absent
    exec_ = FakeExecutor([])
    monkeypatch.setattr(vulnscan, "get_executor", lambda timeout=30: exec_)
    out = _audit(SystemPatchAuditInput(
        host="10.0.0.5", user="Administrator", password="pw"
    ))
    assert "sshpass" in out
    assert exec_.calls == []


def test_unsupported_family_falls_back_to_inventory(tmp_path, workdir,
                                                    shim_dir, monkeypatch):
    monkeypatch.setenv(vulnscan.VULS2_DB_PATH_ENV, str(tmp_path / "vuls.db"))
    _write_scan_result(workdir, _base_scan("kali", release="rolling",
                                           packages={
                                               "bash": {"name": "bash",
                                                        "version": "5.2.15",
                                                        "newVersion": "5.2.21"},
                                           }))
    exec_ = FakeExecutor([
        (lambda c: c[0].endswith("ssh-keyscan"), _ok(stdout="x ssh-rsa k")),
        (lambda c: len(c) > 1 and c[1] == "scan", _ok()),
        (lambda c: len(c) > 1 and c[1] == "report",
         _err("Failed to detect. Unsupported detection methods for kali")),
    ])
    monkeypatch.setattr(vulnscan, "get_executor", lambda timeout=30: exec_)

    out = _audit(SystemPatchAuditInput(host="127.0.0.1", user="xhj"))
    assert "系统补丁清单" in out
    assert "bash" in out
    assert "5.2.21" in out
    assert "不支持" in out


def test_severity_filter_and_max_results(tmp_path, workdir, shim_dir,
                                         monkeypatch):
    monkeypatch.setenv(vulnscan.VULS2_DB_PATH_ENV, str(tmp_path / "vuls.db"))
    cves = {}
    for i, (score, sev) in enumerate([
        (9.8, "CRITICAL"), (9.1, "CRITICAL"), (8.0, "HIGH"),
        (5.0, "MEDIUM"), (2.0, "LOW"),
    ]):
        cves[f"CVE-2026-{i:04d}"] = {
            "cveID": f"CVE-2026-{i:04d}",
            "affectedPackages": [],
            "cveContents": {"nvd": [{
                "cveID": f"CVE-2026-{i:04d}",
                "title": f"vuln {i}",
                "cvss3Score": score,
                "cvss3Severity": sev,
                "sourceLink": f"https://example.com/{i}",
                "references": [],
            }]},
        }
    _write_scan_result(workdir, _base_scan("debian", release="13"))

    def report_side_effect(cmd):
        for f in (workdir / "results").glob("*/*.json"):
            d = json.loads(f.read_text(encoding="utf-8"))
            d["scannedCves"] = cves
            f.write_text(json.dumps(d), encoding="utf-8")
        return _ok()

    exec_ = FakeExecutor([
        (lambda c: c[0].endswith("ssh-keyscan"), _ok(stdout="x ssh-rsa k")),
        (lambda c: len(c) > 1 and c[1] == "scan", _ok()),
        (lambda c: len(c) > 1 and c[1] == "report",
         lambda c: report_side_effect(c)),
    ])
    monkeypatch.setattr(vulnscan, "get_executor", lambda timeout=30: exec_)

    out = _audit(SystemPatchAuditInput(
        host="10.0.0.9", user="root", severity="high", max_results=2
    ))
    # Only critical+high pass the filter; at most 2 are listed.
    assert "CVE-2026-0000" in out
    assert "CVE-2026-0001" in out
    for hidden in ("CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"):
        assert hidden not in out
    # The summary table still counts all 5
    assert "| 5 |" in out or "5 个" in out


def test_scan_failure_reports_tail(tmp_path, workdir, shim_dir, monkeypatch):
    monkeypatch.setenv(vulnscan.VULS2_DB_PATH_ENV, str(tmp_path / "vuls.db"))
    exec_ = FakeExecutor([
        (lambda c: c[0].endswith("ssh-keyscan"), _ok(stdout="x ssh-rsa k")),
        (lambda c: len(c) > 1 and c[1] == "scan",
         _err("ssh: connect to host 10.0.0.99 port 22: No route to host")),
    ])
    monkeypatch.setattr(vulnscan, "get_executor", lambda timeout=30: exec_)

    out = _audit(SystemPatchAuditInput(host="10.0.0.99", user="root"))
    assert "扫描失败" in out
    assert "No route to host" in out
    # Workdir retained for debugging on failure
    assert os.path.isdir(str(workdir))


def test_keyscan_failure_is_clear(tmp_path, workdir, shim_dir, monkeypatch):
    monkeypatch.setenv(vulnscan.VULS2_DB_PATH_ENV, str(tmp_path / "vuls.db"))
    exec_ = FakeExecutor([
        (lambda c: c[0].endswith("ssh-keyscan"), _ok(stdout="")),
    ])
    monkeypatch.setattr(vulnscan, "get_executor", lambda timeout=30: exec_)

    out = _audit(SystemPatchAuditInput(host="10.0.0.99", user="root"))
    assert "host key" in out
