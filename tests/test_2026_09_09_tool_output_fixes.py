"""Tests for the 2026-09-09 tool-output defect fixes (all reproduced live first).

1. http_request discarded ALL response headers (curl -s without -i): the
   agent could not see status codes or Set-Cookie, and a 401 was reported
   as "✓ Success" — session-based auth testing was impossible.
   Fix: curl -s -i (header section + body in the report).

2. ffuf_fuzz parsed only stderr for findings, but ffuf v2 (-noninteractive)
   writes finding lines to stdout while the banner/progress always go to
   stderr → stderr was never empty → EVERY result was missed (100% miss
   rate: known-existing paths reported as "未发现").
   Fix: parse the combined stdout+stderr stream.

3. masscan_scan silently reported "扫描完成 — 未发现开放端口" on
   TUN-routed targets (Tailscale/WireGuard) where masscan cannot work at
   all (live-verified: nmap 8/8 open, masscan found=0 even as root).
   Fix: detect the routing interface; if it is a TUN device, emit a loud
   warning instead of a "clean" result; non-TUN empty results get a
   cross-check hint.

4. hydra_brute with service=rdp: hydra's experimental rdp module reports
   fabricated passwords as "valid pair" against xrdp (reproduced with a
   made-up password on the user's own xrdp host).
   Fix: loud false-positive warning on all rdp outputs.
"""

from __future__ import annotations

import asyncio

import pytest

from kali_mcp.executor import CommandResult
from kali_mcp.pentest import HydraInput, hydra_brute
from kali_mcp.tools import (
    CurlInput,
    MasscanInput,
    http_request,
    masscan_scan,
)
from kali_mcp.vulnscan import FfufInput, ffuf_fuzz


def _run(coro):
    return asyncio.run(coro)


# ===================================================================
# 1. http_request — response headers must be visible
# ===================================================================


class TestHttpRequestHeaders:
    def test_cmd_includes_i_flag(self, monkeypatch):
        import kali_mcp.tools as t

        captured = {}

        class _Ex:
            async def run(self, cmd, timeout=None, input_data=None):
                captured["cmd"] = cmd
                return CommandResult(
                    stdout="HTTP/1.0 200 OK\nServer: BaseHTTP/0.6\n"
                    "Set-Cookie: sid=deadbeef1234; Path=/; HttpOnly\n\n"
                    "cookie-test-ok",
                    stderr="",
                    returncode=0,
                    success=True,
                )

        monkeypatch.setattr(t, "get_executor", lambda timeout=None: _Ex())
        out = _run(http_request(CurlInput(url="http://192.168.0.77/", method="GET")))
        assert "-i" in captured["cmd"]
        # the header section must survive into the report
        assert "Set-Cookie" in out
        assert "HTTP/1.0 200 OK" in out

    def test_401_status_line_visible(self, monkeypatch):
        """Regression: a 401 was previously reported as '✓ Success' with
        no way to see the status code."""
        import kali_mcp.tools as t

        class _Ex:
            async def run(self, cmd, timeout=None, input_data=None):
                return CommandResult(
                    stdout=(
                        "HTTP/1.1 401 UNAUTHORIZED\n"
                        "Content-Type: application/json\n\n"
                        '{"code": "AUTH_REQUIRED", "success": false}'
                    ),
                    stderr="",
                    returncode=0,
                    success=True,
                )

        monkeypatch.setattr(t, "get_executor", lambda timeout=None: _Ex())
        out = _run(http_request(CurlInput(url="http://192.168.0.77/api/health")))
        assert "HTTP/1.1 401" in out
        assert "AUTH_REQUIRED" in out


# ===================================================================
# 2. ffuf_fuzz — findings live on stdout, banner on stderr
# ===================================================================


class TestFfufStreamParsing:
    def _patch(self, monkeypatch, stdout, stderr):
        import kali_mcp.vulnscan as v

        class _Ex:
            async def run(self, cmd, timeout=None, input_data=None):
                # live-verified ffuf 2.1.0 stream layout:
                # findings -> stdout, banner/progress -> stderr
                return CommandResult(
                    stdout=stdout, stderr=stderr, returncode=0, success=True
                )

        monkeypatch.setattr(v, "get_executor", lambda timeout=None: _Ex())

    def test_finding_on_stdout_reported_despite_nonempty_stderr(self, monkeypatch):
        """The exact regression: known-existing /login (200) on stdout,
        banner+progress on stderr — old code reported '未发现'."""
        self._patch(
            monkeypatch,
            stdout=(
                "login                   [Status: 200, Size: 5467, "
                "Words: 1855, Lines: 152, Duration: 16ms]"
            ),
            stderr=(
                "ffuf v2.1.0-dev\n"
                " :: Method           : GET\n"
                " :: Progress: [16/16] :: Job [1/1] :: Errors: 0 ::"
            ),
        )
        out = _run(
            ffuf_fuzz(
                FfufInput(
                    url="http://192.168.0.77/FUZZ",
                    wordlist="/usr/share/wordlists/dirb/common.txt",
                )
            )
        )
        assert "login" in out
        assert "200" in out
        assert "未发现" not in out

    def test_truly_empty_run_still_reports_none(self, monkeypatch):
        self._patch(
            monkeypatch,
            stdout="",
            stderr="ffuf v2.1.0-dev\n :: Progress: [4600/4600] :: Errors: 0 ::",
        )
        out = _run(
            ffuf_fuzz(
                FfufInput(
                    url="http://192.168.0.77/FUZZ",
                    wordlist="/usr/share/wordlists/dirb/common.txt",
                )
            )
        )
        assert "未发现匹配的路径/参数" in out


class TestIsTunInterface:
    def test_rejects_unsafe_names(self):
        import kali_mcp.tools as t

        assert t._is_tun_interface("") is False
        assert t._is_tun_interface("../etc") is False
        assert t._is_tun_interface("a/b") is False

    def test_type_65534_is_tun(self, monkeypatch):
        import io

        import kali_mcp.tools as t

        def fake_open(path, *a, **k):
            assert path == "/sys/class/net/wg0/type"
            # ARPHRD_TUN = 65534 (live-verified on tailscale0)
            return io.StringIO("65534\n")

        monkeypatch.setattr("builtins.open", fake_open)
        assert t._is_tun_interface("wg0") is True

    def test_other_type_is_not_tun(self, monkeypatch):
        import io

        import kali_mcp.tools as t

        monkeypatch.setattr(
            "builtins.open", lambda *a, **k: io.StringIO("1\n")
        )
        assert t._is_tun_interface("eth0") is False

    def test_missing_sysfs_is_not_tun(self, monkeypatch):
        import kali_mcp.tools as t

        def fake_open(path, *a, **k):
            raise FileNotFoundError(path)

        monkeypatch.setattr("builtins.open", fake_open)
        assert t._is_tun_interface("nope0") is False


class TestFfufVhostCmd:
    def test_vhost_default_wordlist_keeps_w_flag(self, monkeypatch):
        """Regression: cmd[3] (the -w flag itself) was overwritten with the
        subdomain wordlist path, silently dropping the wordlist flag."""
        import kali_mcp.vulnscan as v

        captured = {}

        class _Ex:
            async def run(self, cmd, timeout=None, input_data=None):
                captured["cmd"] = list(cmd)
                return CommandResult(
                    stdout="", stderr="banner", returncode=0, success=True
                )

        monkeypatch.setattr(v, "get_executor", lambda timeout=None: _Ex())
        _run(
            ffuf_fuzz(
                FfufInput(url="http://192.168.0.77/FUZZ", mode="vhost")
            )
        )
        cmd = captured["cmd"]
        assert "-w" in cmd
        assert cmd[cmd.index("-w") + 1] == (
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        )
        assert "-H" in cmd and cmd[cmd.index("-H") + 1] == "Host: FUZZ"


# ===================================================================
# 3. masscan_scan — TUN-routed targets must not report "clean"
# ===================================================================


class TestMasscanTunWarning:
    def _patch(self, monkeypatch, route_out, scan_result, tun_ifs):
        import kali_mcp.tools as t

        class _Ex:
            cmds: list[list[str]] = []

            async def run(self, cmd, timeout=None, input_data=None):
                _Ex.cmds.append(list(cmd))
                if cmd[0] == "ip":
                    return CommandResult(
                        stdout=route_out, stderr="", returncode=0, success=True
                    )
                return scan_result

        ex = _Ex()
        monkeypatch.setattr(t, "get_executor", lambda timeout=None: ex)
        monkeypatch.setattr(t, "_is_tun_interface", lambda dev: dev in tun_ifs)
        return ex

    def test_tun_route_emits_warning_not_clean(self, monkeypatch):
        # live-verified route line shape on Kali (Tailscale, no "via"):
        ex = self._patch(
            monkeypatch,
            route_out=(
                "100.101.108.100 dev tailscale0 table 52 "
                "src 100.101.105.100 uid 0"
            ),
            scan_result=CommandResult(
                stdout="Starting masscan 1.3.2\nFinished scan",
                stderr="rate:  0.00-kpps, 100.00% done, found=0",
                returncode=0,
                success=True,
            ),
            tun_ifs={"tailscale0"},
        )
        out = _run(masscan_scan(MasscanInput(target="100.101.108.100", ports="22,80")))
        # route probe happened first, with the target's first address
        assert ex.cmds[0][:3] == ["ip", "route", "get"]
        assert ex.cmds[0][3] == "100.101.108.100"
        # loud warning instead of a silent "clean"
        assert "TUN" in out
        assert "tailscale0" in out
        assert "nmap_scan" in out

    def test_non_tun_empty_gets_crosscheck_hint_only(self, monkeypatch):
        self._patch(
            monkeypatch,
            route_out="192.168.0.5 via 192.168.0.1 dev eth0 src 192.168.0.2 uid 1000",
            scan_result=CommandResult(
                stdout="Starting masscan 1.3.2\nFinished scan",
                stderr="rate:  50-kpps, 100.00% done, found=0",
                returncode=0,
                success=True,
            ),
            tun_ifs=set(),
        )
        out = _run(masscan_scan(MasscanInput(target="192.168.0.5", ports="22,80")))
        assert "TUN" not in out
        # plain empty result still cross-checkable
        assert "未发现开放端口" in out
        assert "nmap_scan" in out

    def test_found_ports_summary_unchanged(self, monkeypatch):
        self._patch(
            monkeypatch,
            route_out="192.168.0.5 via 192.168.0.1 dev eth0 src 192.168.0.2 uid 1000",
            scan_result=CommandResult(
                stdout="Discovered open port 80/tcp on 192.168.0.68",
                stderr="rate:  50-kpps, 100.00% done, found=1",
                returncode=0,
                success=True,
            ),
            tun_ifs=set(),
        )
        out = _run(masscan_scan(MasscanInput(target="192.168.0.5", ports="80")))
        assert "192.168.0.68" in out
        assert "未发现开放端口" not in out

    def test_route_probe_failure_never_blocks_scan(self, monkeypatch):
        ex = self._patch(
            monkeypatch,
            route_out="",
            scan_result=CommandResult(
                stdout="Discovered open port 22/tcp on 192.168.0.68",
                stderr="",
                returncode=0,
                success=True,
            ),
            tun_ifs=set(),
        )
        # 'ip route get' returns nothing -> no dev match -> no warning,
        # scan output intact
        out = _run(masscan_scan(MasscanInput(target="192.168.0.5", ports="22")))
        assert "192.168.0.68" in out
        assert "TUN" not in out


# ===================================================================
# 4. hydra_brute — rdp outputs carry the false-positive warning
# ===================================================================


class TestHydraRdpWarning:
    def _patch(self, monkeypatch):
        import kali_mcp.pentest as p

        class _Ex:
            async def run(self, cmd, timeout=None, input_data=None):
                return CommandResult(
                    stdout=(
                        "Hydra v9.7 starting\n"
                        "[DATA] attacking rdp://192.168.0.77:3389/\n"
                        "[STATUS] attack finished for 192.168.0.77 (no valid pair found)"
                    ),
                    stderr="",
                    returncode=0,
                    success=True,
                )

        monkeypatch.setattr(p, "get_executor", lambda timeout=None: _Ex())

    def test_rdp_gets_false_positive_warning(self, monkeypatch):
        self._patch(monkeypatch)
        out = _run(
            hydra_brute(
                HydraInput(
                    target="192.168.0.77",
                    service="rdp",
                    username="probeuser",
                    password_file="/tmp/pw.txt",
                )
            )
        )
        assert "误报" in out
        assert "xrdp" in out
        assert "不得直接使用" in out

    def test_non_rdp_service_has_no_rdp_warning(self, monkeypatch):
        self._patch(monkeypatch)
        out = _run(
            hydra_brute(
                HydraInput(
                    target="192.168.0.77",
                    service="ssh",
                    username="probeuser",
                    password_file="/tmp/pw.txt",
                )
            )
        )
        assert "误报" not in out
