"""Tests for parsing logic of the new tools:

- ssl_cert_check  (vulnscan.py): PEM extraction, date parsing, status, x509 summary
- http_load_test  (pentest.py): Apache Bench output parsing
- firewall_rules  (tools.py): nftables rule counting
"""

from datetime import datetime, timedelta, timezone

import pytest

from kali_mcp.pentest import _parse_ab_output
from kali_mcp.tools import _count_nft_rules
from kali_mcp.vulnscan import (
    _cert_status,
    _extract_cert_pem,
    _parse_openssl_date,
    _parse_x509_summary,
)

# ---------------------------------------------------------------------------
# Fixtures / sample outputs
# ---------------------------------------------------------------------------

_FAKE_PEM_BODY = "MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkj" + "A0GAw0EAoGA" * 3


def _sclient_output(with_cert: bool = True) -> str:
    pem_block = (
        f"-----BEGIN CERTIFICATE-----\n{_FAKE_PEM_BODY}\n-----END CERTIFICATE-----"
        if with_cert
        else ""
    )
    return "\n".join(
        [
            "CONNECTED(00000003)",
            "---",
            "Certificate chain",
            " 0 s:C = CN, O = Let's Encrypt, CN = example.com",
            "   i:C = US, O = Internet Security Research Group, CN = R11",
            pem_block,
            "---",
            "SSL handshake has read 2456 bytes and written 468 bytes",
            "Verification: OK",
            "---",
            "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384",
            "Server public key is 2048 bit",
            "SSL-Session:",
            "    Protocol  : TLSv1.3",
            "    Cipher    : TLS_AES_256_GCM_SHA384",
            "Verify return code: 0 (ok)",
            "---",
            "DONE",
        ]
    )


_X509_OUT = """\
subject=C = CN, O = Let's Encrypt, CN = example.com
issuer=C = US, O = Internet Security Research Group, CN = R11
notBefore=May  1 00:00:00 2025 GMT
notAfter=Jul 30 23:59:59 2025 GMT
X509v3 Subject Alternative Name: 
    DNS:example.com, DNS:www.example.com, IP Address:93.184.216.34
"""

_AB_OUT = """\
This is Apache Bench version 2.3 ASCII website load tester.
Benchmarking example.com (beating)
Completed 100 requests
Finished 1000 requests


Server Software:        nginx/1.24.0
Server Hostname:        example.com
Server Port:            80

Document Path:          /
Document Length:        612 bytes

Concurrency Level:      10
Time taken for tests:   3.215 seconds
Complete requests:      1000
Failed requests:        0
Total transferred:      748000 bytes
HTML transferred:       612000 bytes
Requests per second:    311.04 [#/sec] (mean)
Time per request:       32.150 [ms] (mean)
Time per request:       3.215 [ms] (mean, across all concurrent requests)

Percentage of the requests served within millisecond(s):

50%    28
66%    31
75%    34
80%    36
90%    42
99%   120

Status code distribution:
200 1000


End of report
"""

_NFT_RULESET = """\
table inet filter {
	chain INPUT {
		type filter hook input priority 0; policy accept;
		tcp dport 22 ct state established,related accept
		tcp dport 22 tcp flags syn drop
	}
	chain FORWARD {
		type filter hook forward priority 0; policy drop;
	}
}
"""


# ---------------------------------------------------------------------------
# ssl_cert_check — PEM extraction
# ---------------------------------------------------------------------------

class TestExtractCertPem:
    def test_extracts_first_pem_block(self):
        pem = _extract_cert_pem(_sclient_output())
        assert pem is not None
        assert pem.startswith("-----BEGIN CERTIFICATE-----\n")
        assert pem.endswith("\n-----END CERTIFICATE-----")
        assert _FAKE_PEM_BODY in pem

    def test_no_cert_returns_none(self):
        out = "CONNECTED(00000003)\nno handshake happened\n"
        assert _extract_cert_pem(out) is None

    def test_empty_output_returns_none(self):
        assert _extract_cert_pem("") is None


# ---------------------------------------------------------------------------
# ssl_cert_check — date parsing & status
# ---------------------------------------------------------------------------

class TestOpensslDate:
    def test_parses_double_space_day(self):
        dt = _parse_openssl_date("May  1 00:00:00 2025 GMT")
        assert dt == datetime(2025, 5, 1, 0, 0, 0, tzinfo=timezone.utc)

    def test_parses_single_digit_day(self):
        dt = _parse_openssl_date("Jul 30 23:59:59 2025 GMT")
        assert dt == datetime(2025, 7, 30, 23, 59, 59, tzinfo=timezone.utc)

    @pytest.mark.parametrize("bad", ["not a date", "2025-13-45", "", "GMT"])
    def test_invalid_returns_none(self, bad):
        assert _parse_openssl_date(bad) is None


class TestCertStatus:
    NOW = datetime(2025, 7, 1, 12, 0, tzinfo=timezone.utc)

    def test_valid_far_future(self):
        label, days = _cert_status(self.NOW + timedelta(days=400), self.NOW)
        assert "🟢" in label and days == 400

    def test_warning_under_30_days(self):
        label, days = _cert_status(self.NOW + timedelta(days=20), self.NOW)
        assert "🟡" in label and days == 20

    def test_critical_under_7_days(self):
        label, days = _cert_status(self.NOW + timedelta(days=3), self.NOW)
        assert "🟠" in label and days == 3

    def test_expired(self):
        label, days = _cert_status(self.NOW - timedelta(days=10), self.NOW)
        assert "🔴" in label and "EXPIRED" in label and days == -10

    def test_unparseable_date(self):
        label, days = _cert_status(None, self.NOW)
        assert "❓" in label and days is None


# ---------------------------------------------------------------------------
# ssl_cert_check — x509 summary parsing
# ---------------------------------------------------------------------------

class TestParseX509Summary:
    def test_openssl3_format(self):
        info = _parse_x509_summary(_X509_OUT)
        assert info["subject"] == "C = CN, O = Let's Encrypt, CN = example.com"
        assert info["issuer"].endswith("CN = R11")
        assert info["not_before"] == "May  1 00:00:00 2025 GMT"
        assert info["not_after"] == "Jul 30 23:59:59 2025 GMT"
        assert "DNS:example.com" in info["sans"]
        assert "IP Address:93.184.216.34" in info["sans"]

    def test_legacy_slash_format(self):
        out = (
            "subject=/C=CN/O=ACME/CN=legacy.example\n"
            "issuer=/C=US/O=CA/CN=R10\n"
            "notBefore=Jan  5 08:30:00 2024 GMT\n"
            "notAfter=Feb  4 08:30:00 2026 GMT\n"
        )
        info = _parse_x509_summary(out)
        assert info["subject"] == "/C=CN/O=ACME/CN=legacy.example"
        assert info["sans"] == ""

    def test_empty_output(self):
        info = _parse_x509_summary("")
        assert all(v == "" for v in info.values())


# ---------------------------------------------------------------------------
# http_load_test — ab output parsing
# ---------------------------------------------------------------------------

class TestParseAbOutput:
    def test_full_benchmark(self):
        m = _parse_ab_output(_AB_OUT)
        assert m["rps"] == 311.04
        assert m["elapsed_s"] == 3.215
        assert m["complete"] == 1000
        assert m["failed"] == 0
        # First "Time per request" line is the overall mean (ms)
        assert m["mean_ms"] == 32.150
        assert m["server_software"].strip() == "nginx/1.24.0"
        assert m["total_bytes"] == 748000
        assert m["percentiles"] == {50: 28, 66: 31, 75: 34, 80: 36, 90: 42, 99: 120}

    def test_garbage_returns_empty(self):
        assert _parse_ab_output("ab: invalid options") == {}

    def test_partial_output(self):
        m = _parse_ab_output(
            "Complete requests:      50\n"
            "Failed requests:        2\n"
        )
        assert m["complete"] == 50
        assert m["failed"] == 2
        assert "rps" not in m and "percentiles" not in m


# ---------------------------------------------------------------------------
# firewall_rules — nftables rule counting
# ---------------------------------------------------------------------------

class TestCountNftRules:
    def test_counts_verdict_lines_only(self):
        # 2 real rules; the two "policy ..." chain headers must NOT count.
        assert _count_nft_rules(_NFT_RULESET) == 2

    def test_empty_ruleset(self):
        assert _count_nft_rules("") == 0

    def test_drop_and_reject_verdicts(self):
        ruleset = (
            "table inet f {\n"
            "\tchain X { type filter hook input priority 0; policy drop;\n"
            "\t\tip daddr 10.0.0.5 reject\n"
            "\t\tdrop\n"
            "\t}\n"
            "}\n"
        )
        assert _count_nft_rules(ruleset) == 2
