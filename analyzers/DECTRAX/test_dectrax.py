"""Unit tests for DECTRAX Cortex Analyzer."""

import pytest
from unittest.mock import MagicMock, patch
from dectrax import DECTRAXAnalyzer


def test_dectrax_analyzer_init():
    analyzer = DECTRAXAnalyzer()
    assert analyzer.url == "https://api.dectrax.com"
    assert analyzer.cert_check is True


def test_summary_blocked():
    analyzer = DECTRAXAnalyzer()
    raw = {"blocked": True, "interactions": 5}
    summary = analyzer.summary(raw)
    assert len(summary["taxonomies"]) == 1
    tax = summary["taxonomies"][0]
    assert tax["level"] == "malicious"
    assert tax["namespace"] == "DECTRAX"
    assert tax["predicate"] == "Interdiction"
    assert "Blocked in Firewall EDL" in tax["value"]


def test_summary_suspicious():
    analyzer = DECTRAXAnalyzer()
    raw = {"blocked": False, "interactions": 3}
    summary = analyzer.summary(raw)
    assert len(summary["taxonomies"]) == 1
    tax = summary["taxonomies"][0]
    assert tax["level"] == "suspicious"
    assert tax["predicate"] == "Deception"
    assert "3 Decoy Interactions" in tax["value"]


def test_summary_clean():
    analyzer = DECTRAXAnalyzer()
    raw = {"blocked": False, "interactions": 0}
    summary = analyzer.summary(raw)
    assert len(summary["taxonomies"]) == 1
    tax = summary["taxonomies"][0]
    assert tax["level"] == "safe"
    assert tax["predicate"] == "Status"
    assert tax["value"] == "Clean"


def test_check_edl_blocklist():
    analyzer = DECTRAXAnalyzer()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "192.0.2.1\n198.51.100.22\n203.0.113.50\n"

    with patch.object(analyzer.session, "get", return_value=mock_response):
        assert analyzer.check_edl_blocklist("198.51.100.22") is True
        assert analyzer.check_edl_blocklist("8.8.8.8") is False
