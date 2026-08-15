"""Tests for nuclei templates directory resolution (vulnscan.py).

The resolver is pure logic (env var + filesystem probing), so these
tests run on any platform without nuclei installed.
"""

import pytest

from kali_mcp import vulnscan


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Ensure NUCLEI_TEMPLATES_DIR is unset unless a test sets it."""
    monkeypatch.delenv(vulnscan.NUCLEI_TEMPLATES_DIR_ENV, raising=False)


class TestResolveTemplatesDir:
    def test_override_env_used_when_set_and_exists(self, monkeypatch, tmp_path):
        tpl = tmp_path / "templates"
        tpl.mkdir()
        monkeypatch.setenv(vulnscan.NUCLEI_TEMPLATES_DIR_ENV, str(tpl))
        assert vulnscan._resolve_templates_dir() == str(tpl)

    def test_override_authoritative_even_when_missing(self, monkeypatch, tmp_path):
        # Explicit override wins: a wrong value must NOT silently fall back
        # to an auto-detected path (that would mask a misconfiguration).
        home = tmp_path / "home"
        (home / "nuclei-templates").mkdir(parents=True)  # would be found otherwise
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv(
            vulnscan.NUCLEI_TEMPLATES_DIR_ENV, str(tmp_path / "nope")
        )
        assert vulnscan._resolve_templates_dir() is None

    def test_fallback_home_nuclei_templates(self, monkeypatch, tmp_path):
        home = tmp_path / "home"
        (home / "nuclei-templates").mkdir(parents=True)
        monkeypatch.setenv("HOME", str(home))
        assert vulnscan._resolve_templates_dir() == str(home / "nuclei-templates")

    def test_fallback_xdg_local_nuclei_templates(self, monkeypatch, tmp_path):
        home = tmp_path / "home"
        (home / ".local" / "nuclei-templates").mkdir(parents=True)
        monkeypatch.setenv("HOME", str(home))
        assert (
            vulnscan._resolve_templates_dir()
            == str(home / ".local" / "nuclei-templates")
        )

    def test_home_candidate_priority(self, monkeypatch, tmp_path):
        # "~/nuclei-templates" comes before "~/.local/nuclei-templates"
        home = tmp_path / "home"
        (home / "nuclei-templates").mkdir(parents=True)
        (home / ".local" / "nuclei-templates").mkdir(parents=True)
        monkeypatch.setenv("HOME", str(home))
        assert vulnscan._resolve_templates_dir() == str(home / "nuclei-templates")

    def test_non_home_candidates_probed(self, monkeypatch, tmp_path):
        # Simulates templates under a path not derived from $HOME (e.g. a
        # root-run server); the candidate list must still be walked.
        monkeypatch.setenv("HOME", str(tmp_path / "empty-home"))
        monkeypatch.setattr(
            vulnscan,
            "_DEFAULT_TEMPLATES_CANDIDATES",
            (str(tmp_path / "root-tpl"),),
        )
        (tmp_path / "root-tpl").mkdir()
        assert vulnscan._resolve_templates_dir() == str(tmp_path / "root-tpl")

    def test_none_when_nothing_exists(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HOME", str(tmp_path / "empty-home"))
        assert vulnscan._resolve_templates_dir() is None
