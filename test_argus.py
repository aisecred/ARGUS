"""
test_argus.py — Test suite for argus.py

Covers: ReconDB schema/CRUD, confidence scoring, delta reporting,
exports, LLM analysis, config loading, helpers, and wildcard detection.

Run:
    pytest test_argus.py -v
    pytest test_argus.py -v -k "TestReconDB"
"""

import csv
import json
import os
import sqlite3
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import argus as m
from argus import (
    ReconDB,
    apply_preset,
    detect_wildcard_dns,
    find_recon_db_files,
    generate_delta_report,
    generate_llm_analysis,
    load_config_file,
    merge_recon_databases,
    query_shodan,
    query_censys,
    query_virustotal,
    run_api_enrichment,
    _ptr_confidence,
    _classify_cname,
    _check_resolves,
    _analyze_spf,
    _analyze_dmarc,
    _analyze_dkim,
    _analyze_mta_sts,
    _email_risk_score,
    _estimate_rsa_bits,
    _spf_lookup_count,
    _identify_mx_provider,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_db(tmp_path):
    """Return a fresh ReconDB backed by a temp file."""
    return ReconDB(str(tmp_path / "recon.db"))


@pytest.fixture
def populated_db(tmp_db):
    """ReconDB with a handful of assets for query tests."""
    tmp_db.update_asset("example.com",   confidence=100, ip="1.2.3.4",   asn="AS15169", cdn="Cloudflare",  tech_stack="nginx",  status_code=200)
    tmp_db.update_asset("api.example.com", confidence=85, ip="1.2.3.5",  asn="AS15169", cdn="Cloudflare",  tech_stack="nginx",  status_code=200)
    tmp_db.update_asset("dev.example.com", confidence=85, ip="5.5.5.5",  asn="AS15169", cdn="No",          tech_stack="apache", status_code=200)
    tmp_db.update_asset("old.example.com", confidence=40, ip="9.9.9.9",  asn="AS9876",  cdn="No",          status_code=404)
    tmp_db.update_asset("dead.example.com", confidence=60, ip="2.2.2.2", asn="AS15169", cdn="No",          is_live=0)
    return tmp_db


def _fake_args(**kwargs):
    defaults = dict(
        domain=None, domain_file=None, outdir="recon_results", verbose=False,
        target_conf=0, httpx=False, gowitness=False, tech_stack_enum=False,
        nuclei=False, geolocate=False, reverse_dns=False, asnmap=False,
        llm_analysis=False, diff=False, export_csv=False, export_json=False,
        html_report=False, preset=None, resume=False, proxy=None,
        user_agent=None, rate_limit=0, stealth=False, min_conf=0,
        workers=8, ports="80,443", webhook=None, webhook_include_assets=False,
        webhook_max_assets=50, merge_dirs=None, merge_recursive=None,
        merge_only=False, query=False, config=None,
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


# ── TestReconDB ───────────────────────────────────────────────────────────────

class TestReconDB:
    def test_setup_creates_assets_table(self, tmp_db):
        with tmp_db._connection() as conn:
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='assets'"
            ).fetchone()
        assert row is not None

    def test_setup_creates_scans_table(self, tmp_db):
        with tmp_db._connection() as conn:
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='scans'"
            ).fetchone()
        assert row is not None

    def test_setup_creates_confidence_index(self, tmp_db):
        with tmp_db._connection() as conn:
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_assets_confidence'"
            ).fetchone()
        assert row is not None

    def test_cidr_column_exists(self, tmp_db):
        with tmp_db._connection() as conn:
            cols = [r[1] for r in conn.execute("PRAGMA table_info(assets)").fetchall()]
        assert "cidr" in cols

    def test_geolocation_column_exists(self, tmp_db):
        with tmp_db._connection() as conn:
            cols = [r[1] for r in conn.execute("PRAGMA table_info(assets)").fetchall()]
        assert "geolocation" in cols

    def test_column_migration_on_existing_db(self, tmp_path):
        """Opening a legacy DB without cidr/geolocation columns should add them."""
        db_path = str(tmp_path / "legacy.db")
        conn = sqlite3.connect(db_path)
        conn.execute("""CREATE TABLE assets (
            host TEXT PRIMARY KEY, ip TEXT, asn TEXT, cdn TEXT,
            confidence INTEGER DEFAULT 0, discovery_reason TEXT,
            web_title TEXT, status_code INTEGER, tech_stack TEXT,
            open_ports TEXT, vulns TEXT, is_live INTEGER DEFAULT 1,
            first_seen TEXT, last_seen TEXT, last_scanned TEXT,
            tools_run TEXT, screenshot_path TEXT
        )""")
        conn.commit()
        conn.close()

        db = ReconDB(db_path)
        with db._connection() as c:
            cols = [r[1] for r in c.execute("PRAGMA table_info(assets)").fetchall()]
        assert "cidr" in cols
        assert "geolocation" in cols

    def test_wal_mode(self, tmp_db):
        with tmp_db._connection() as conn:
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"


# ── TestUpdateAsset ───────────────────────────────────────────────────────────

class TestUpdateAsset:
    def test_basic_insert(self, tmp_db):
        tmp_db.update_asset("example.com", confidence=100)
        assert tmp_db.get_total_count() == 1

    def test_update_existing(self, tmp_db):
        tmp_db.update_asset("example.com", confidence=40)
        tmp_db.update_asset("example.com", confidence=85)
        assert tmp_db.get_total_count() == 1
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT confidence FROM assets WHERE host='example.com'").fetchone()
        assert row[0] == 85

    def test_empty_host_returns_early(self, tmp_db):
        tmp_db.update_asset("")
        tmp_db.update_asset(None)
        assert tmp_db.get_total_count() == 0

    def test_host_with_port_stripped(self, tmp_db):
        tmp_db.update_asset("example.com:443", confidence=80)
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT host FROM assets").fetchone()
        assert row[0] == "example.com"

    def test_host_lowercased(self, tmp_db):
        tmp_db.update_asset("EXAMPLE.COM", confidence=80)
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT host FROM assets").fetchone()
        assert row[0] == "example.com"

    def test_ip_list_normalized_to_string(self, tmp_db):
        tmp_db.update_asset("example.com", ip=["1.2.3.4", "5.6.7.8"])
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT ip FROM assets WHERE host='example.com'").fetchone()
        assert "1.2.3.4" in row[0]
        assert "5.6.7.8" in row[0]

    def test_ip_routing_to_existing_hostname(self, tmp_db):
        tmp_db.update_asset("example.com", ip="1.2.3.4")
        tmp_db.update_asset("1.2.3.4", confidence=90)
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT confidence FROM assets WHERE host='example.com'").fetchone()
        assert row[0] == 90

    def test_unknown_ip_skipped(self, tmp_db):
        tmp_db.update_asset("1.2.3.4", confidence=80)
        assert tmp_db.get_total_count() == 0

    def test_tools_run_accumulates(self, tmp_db):
        tmp_db.update_asset("example.com", tool_name="subfinder")
        tmp_db.update_asset("example.com", tool_name="dnsx")
        tmp_db.update_asset("example.com", tool_name="httpx")
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT tools_run FROM assets WHERE host='example.com'").fetchone()
        tools = {t.strip() for t in row[0].split(",")}
        assert tools == {"subfinder", "dnsx", "httpx"}

    def test_first_seen_set_only_once(self, tmp_db):
        tmp_db.update_asset("example.com", confidence=40)
        with tmp_db._connection() as conn:
            first = conn.execute("SELECT first_seen FROM assets WHERE host='example.com'").fetchone()[0]
        tmp_db.update_asset("example.com", confidence=85)
        with tmp_db._connection() as conn:
            first2 = conn.execute("SELECT first_seen FROM assets WHERE host='example.com'").fetchone()[0]
        assert first == first2

    def test_last_seen_always_updated(self, tmp_db):
        tmp_db.update_asset("example.com", confidence=40)
        with tmp_db._connection() as conn:
            t1 = conn.execute("SELECT last_seen FROM assets WHERE host='example.com'").fetchone()[0]
        import time; time.sleep(1)
        tmp_db.update_asset("example.com", confidence=85)
        with tmp_db._connection() as conn:
            t2 = conn.execute("SELECT last_seen FROM assets WHERE host='example.com'").fetchone()[0]
        assert t2 >= t1

    def test_brand_hint_string_sets_confidence_100(self, tmp_db):
        tmp_db.update_asset("example.com", brand_hint="example", web_title="Example Corp Homepage", confidence=40)
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT confidence FROM assets WHERE host='example.com'").fetchone()
        assert row[0] == 100

    def test_brand_hint_set_sets_confidence_100(self, tmp_db):
        tmp_db.update_asset("example.com", brand_hint={"example", "corp"}, web_title="Example Corp Homepage", confidence=40)
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT confidence FROM assets WHERE host='example.com'").fetchone()
        assert row[0] == 100

    def test_brand_hint_no_match_leaves_confidence(self, tmp_db):
        tmp_db.update_asset("example.com", brand_hint="acme", web_title="Example Corp Homepage", confidence=40)
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT confidence FROM assets WHERE host='example.com'").fetchone()
        assert row[0] == 40

    def test_tech_stack_merges(self, tmp_db):
        tmp_db.update_asset("example.com", tech_stack=["nginx"])
        tmp_db.update_asset("example.com", tech_stack=["php"])
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT tech_stack FROM assets WHERE host='example.com'").fetchone()
        assert "nginx" in row[0]
        assert "php" in row[0]

    def test_open_ports_merges(self, tmp_db):
        tmp_db.update_asset("example.com", open_ports=["80"])
        tmp_db.update_asset("example.com", open_ports=["443"])
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT open_ports FROM assets WHERE host='example.com'").fetchone()
        assert "80" in row[0]
        assert "443" in row[0]

    def test_vulns_merges(self, tmp_db):
        tmp_db.update_asset("example.com", vulns=["CVE-2024-001(high)"])
        tmp_db.update_asset("example.com", vulns=["CVE-2024-002(medium)"])
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT vulns FROM assets WHERE host='example.com'").fetchone()
        assert "CVE-2024-001" in row[0]
        assert "CVE-2024-002" in row[0]

    def test_none_values_filtered_from_list_columns(self, tmp_db):
        tmp_db.update_asset("example.com", open_ports=[None, "80", None])
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT open_ports FROM assets WHERE host='example.com'").fetchone()
        assert "None" not in (row[0] or "")


# ── TestGetters ───────────────────────────────────────────────────────────────

class TestGetters:
    def test_get_total_count_empty(self, tmp_db):
        assert tmp_db.get_total_count() == 0

    def test_get_total_count_populated(self, populated_db):
        assert populated_db.get_total_count() == 5

    def test_get_hosts_by_confidence_threshold(self, populated_db):
        hosts = populated_db.get_hosts_by_confidence(85)
        assert "example.com" in hosts
        assert "api.example.com" in hosts
        assert "dev.example.com" in hosts
        assert "old.example.com" not in hosts

    def test_get_hosts_by_confidence_excludes_dead(self, populated_db):
        hosts = populated_db.get_hosts_by_confidence(0)
        assert "dead.example.com" not in hosts

    def test_get_hosts_ordered_by_confidence_desc(self, populated_db):
        hosts = populated_db.get_hosts_by_confidence(0)
        assert hosts[0] == "example.com"

    def test_has_run_tool_true(self, tmp_db):
        tmp_db.update_asset("example.com", tool_name="subfinder")
        assert tmp_db.has_run_tool("example.com", "subfinder") is True

    def test_has_run_tool_false(self, tmp_db):
        tmp_db.update_asset("example.com", tool_name="subfinder")
        assert tmp_db.has_run_tool("example.com", "dnsx") is False

    def test_has_run_tool_unknown_host(self, tmp_db):
        assert tmp_db.has_run_tool("nothere.com", "subfinder") is False

    def test_has_run_tool_empty_host(self, tmp_db):
        assert tmp_db.has_run_tool("", "subfinder") is False

    def test_get_summary_counts(self, populated_db):
        s = populated_db.get_summary(0)
        assert s["total"] == 5
        assert s["live"] == 4
        assert s["above"] == 5

    def test_get_summary_min_conf_filter(self, populated_db):
        s = populated_db.get_summary(85)
        assert s["above"] == 3

    def test_get_summary_rows_capped_at_200(self, tmp_db):
        for i in range(250):
            tmp_db.update_asset(f"sub{i}.example.com", confidence=50)
        s = tmp_db.get_summary(0)
        assert len(s["rows"]) == 200
        assert s["total"] == 250


# ── TestScanTracking ──────────────────────────────────────────────────────────

class TestScanTracking:
    def test_record_scan_start_returns_id_and_time(self, tmp_db):
        scan_id, started_at = tmp_db.record_scan_start(["example.com"])
        assert isinstance(scan_id, int)
        assert scan_id >= 1
        assert ":" in started_at

    def test_record_scan_complete(self, tmp_db):
        scan_id, _ = tmp_db.record_scan_start(["example.com"])
        tmp_db.record_scan_complete(scan_id)
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT completed_at FROM scans WHERE id=?", (scan_id,)).fetchone()
        assert row[0] is not None

    def test_multiple_scans_have_unique_ids(self, tmp_db):
        id1, _ = tmp_db.record_scan_start(["example.com"])
        id2, _ = tmp_db.record_scan_start(["example.com"])
        assert id1 != id2

    def test_write_snapshot_creates_file(self, tmp_db, tmp_path):
        snap = str(tmp_path / "snap.json")
        tmp_db.write_snapshot(snap)
        assert os.path.exists(snap)

    def test_write_snapshot_contains_assets(self, tmp_db, tmp_path):
        tmp_db.update_asset("example.com", confidence=100, ip="1.2.3.4")
        snap = str(tmp_path / "snap.json")
        tmp_db.write_snapshot(snap)
        with open(snap) as f:
            data = json.load(f)
        assert "example.com" in data["assets"]
        assert data["assets"]["example.com"]["confidence"] == 100

    def test_write_snapshot_empty_db(self, tmp_db, tmp_path):
        snap = str(tmp_path / "snap.json")
        tmp_db.write_snapshot(snap)
        with open(snap) as f:
            data = json.load(f)
        assert data["assets"] == {}


# ── TestComputeDelta ──────────────────────────────────────────────────────────

class TestComputeDelta:
    def _snap(self, tmp_path, assets: dict):
        snap = str(tmp_path / "snap.json")
        with open(snap, "w") as f:
            json.dump({"snapshot_time": "2024-01-01 00:00:00", "assets": assets}, f)
        return snap

    def test_new_asset_detected(self, tmp_db, tmp_path):
        snap = self._snap(tmp_path, {})
        scan_start = "2024-01-01 00:00:00"
        tmp_db.update_asset("new.example.com", confidence=85)
        # Force first_seen to after scan_start
        with tmp_db._connection() as conn:
            conn.execute("UPDATE assets SET first_seen='2024-01-01 00:00:01' WHERE host='new.example.com'")
            conn.commit()
        delta = tmp_db.compute_delta(snap, scan_start)
        assert any(a["host"] == "new.example.com" for a in delta["new"])

    def test_new_asset_not_flagged_if_old(self, tmp_db, tmp_path):
        snap = self._snap(tmp_path, {})
        scan_start = "2024-01-02 00:00:00"
        tmp_db.update_asset("old.example.com", confidence=85)
        with tmp_db._connection() as conn:
            conn.execute("UPDATE assets SET first_seen='2024-01-01 00:00:00' WHERE host='old.example.com'")
            conn.commit()
        delta = tmp_db.compute_delta(snap, scan_start)
        assert not any(a["host"] == "old.example.com" for a in delta["new"])

    def test_removed_asset_detected(self, tmp_db, tmp_path):
        snap = self._snap(tmp_path, {
            "gone.example.com": {"ip": "1.2.3.4", "confidence": 85, "status_code": 200, "vulns": "", "tech_stack": "", "cdn": "", "asn": ""}
        })
        delta = tmp_db.compute_delta(snap, "2024-01-01 00:00:00")
        assert any(a["host"] == "gone.example.com" for a in delta["removed"])

    def test_changed_ip_detected(self, tmp_db, tmp_path):
        snap = self._snap(tmp_path, {
            "example.com": {"ip": "1.1.1.1", "confidence": 85, "status_code": 200, "vulns": "", "tech_stack": "", "cdn": "", "asn": ""}
        })
        tmp_db.update_asset("example.com", ip="2.2.2.2", confidence=85)
        delta = tmp_db.compute_delta(snap, "2024-01-01 00:00:00")
        changed = [a for a in delta["changed"] if a["host"] == "example.com"]
        assert changed
        assert any("ip" in c for c in changed[0]["changes"])

    def test_changed_confidence_detected(self, tmp_db, tmp_path):
        snap = self._snap(tmp_path, {
            "example.com": {"ip": "1.1.1.1", "confidence": 40, "status_code": None, "vulns": "", "tech_stack": "", "cdn": "", "asn": ""}
        })
        tmp_db.update_asset("example.com", ip="1.1.1.1", confidence=85)
        delta = tmp_db.compute_delta(snap, "2024-01-01 00:00:00")
        changed = [a for a in delta["changed"] if a["host"] == "example.com"]
        assert changed
        assert any("confidence" in c for c in changed[0]["changes"])

    def test_changed_vuln_detected(self, tmp_db, tmp_path):
        snap = self._snap(tmp_path, {
            "example.com": {"ip": "1.1.1.1", "confidence": 85, "status_code": 200, "vulns": "", "tech_stack": "", "cdn": "", "asn": ""}
        })
        tmp_db.update_asset("example.com", ip="1.1.1.1", confidence=85, vulns=["CVE-2024-001(high)"])
        delta = tmp_db.compute_delta(snap, "2024-01-01 00:00:00")
        changed = [a for a in delta["changed"] if a["host"] == "example.com"]
        assert changed
        assert any("vuln" in c for c in changed[0]["changes"])

    def test_unchanged_asset_not_flagged(self, tmp_db, tmp_path):
        snap = self._snap(tmp_path, {
            "example.com": {"ip": "1.1.1.1", "confidence": 85, "status_code": 200, "vulns": "", "tech_stack": "", "cdn": "", "asn": ""}
        })
        tmp_db.update_asset("example.com", ip="1.1.1.1", confidence=85, status_code=200)
        delta = tmp_db.compute_delta(snap, "2024-01-01 00:00:00")
        assert not any(a["host"] == "example.com" for a in delta["changed"])

    def test_missing_snapshot_file_returns_empty_diff(self, tmp_db, tmp_path):
        snap = str(tmp_path / "nonexistent.json")
        delta = tmp_db.compute_delta(snap, "2024-01-01 00:00:00")
        assert delta["removed"] == []

    def test_corrupt_snapshot_handled_gracefully(self, tmp_db, tmp_path):
        snap = str(tmp_path / "snap.json")
        with open(snap, "w") as f:
            f.write("not valid json{{{")
        delta = tmp_db.compute_delta(snap, "2024-01-01 00:00:00")
        assert isinstance(delta, dict)


# ── TestConfidenceRecalculation ───────────────────────────────────────────────

class TestConfidenceRecalculation:
    def test_primary_domain_gets_100(self, tmp_db):
        tmp_db.update_asset("example.com", confidence=40)
        tmp_db.recalculate_confidence(["example.com"], set(), set(), set())
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT confidence FROM assets WHERE host='example.com'").fetchone()
        assert row[0] == 100

    def test_subdomain_gets_85(self, tmp_db):
        tmp_db.update_asset("sub.example.com", confidence=40)
        tmp_db.recalculate_confidence(["example.com"], set(), set(), set())
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT confidence FROM assets WHERE host='sub.example.com'").fetchone()
        assert row[0] == 85

    def test_brand_keyword_in_host_gets_85(self, tmp_db):
        tmp_db.update_asset("example-portal.com", confidence=40)
        tmp_db.recalculate_confidence(["example.com"], set(), set(), {"example"})
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT confidence FROM assets WHERE host='example-portal.com'").fetchone()
        assert row[0] == 85

    def test_tls_san_gets_85(self, tmp_db):
        tmp_db.update_asset("cert.example.com", confidence=40)
        tmp_db.recalculate_confidence([], set(), {"cert.example.com"}, set())
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT confidence FROM assets WHERE host='cert.example.com'").fetchone()
        assert row[0] == 85

    def test_asn_match_gets_70(self, tmp_db):
        tmp_db.update_asset("other.com", confidence=40, asn="AS15169")
        tmp_db.recalculate_confidence([], {"AS15169"}, set(), set())
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT confidence FROM assets WHERE host='other.com'").fetchone()
        assert row[0] == 70

    def test_asn_without_prefix_matches(self, tmp_db):
        tmp_db.update_asset("other.com", confidence=40, asn="15169")
        tmp_db.recalculate_confidence([], {"AS15169"}, set(), set())
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT confidence FROM assets WHERE host='other.com'").fetchone()
        assert row[0] == 70

    def test_no_match_stays_baseline(self, tmp_db):
        tmp_db.update_asset("random.net", confidence=40)
        tmp_db.recalculate_confidence(["example.com"], set(), set(), {"example"})
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT confidence FROM assets WHERE host='random.net'").fetchone()
        assert row[0] == 40

    def test_primary_domain_overrides_asn(self, tmp_db):
        tmp_db.update_asset("example.com", confidence=40, asn="AS15169")
        tmp_db.recalculate_confidence(["example.com"], {"AS15169"}, set(), set())
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT confidence FROM assets WHERE host='example.com'").fetchone()
        assert row[0] == 100


# ── TestMergeDB ───────────────────────────────────────────────────────────────

class TestMergeDB:
    def test_merge_copies_assets(self, tmp_path):
        src_db = ReconDB(str(tmp_path / "src.db"))
        src_db.update_asset("example.com", confidence=85, ip="1.2.3.4")
        src_db.update_asset("api.example.com", confidence=85)

        out_path = str(tmp_path / "out.db")
        count = merge_recon_databases(out_path, [str(tmp_path / "src.db")])
        assert count == 2

        out_db = ReconDB(out_path)
        assert out_db.get_total_count() == 2

    def test_merge_skips_self(self, tmp_path):
        db_path = str(tmp_path / "recon.db")
        db = ReconDB(db_path)
        db.update_asset("example.com", confidence=85)
        count = merge_recon_databases(db_path, [db_path])
        assert count == 0

    def test_merge_empty_source_list(self, tmp_path):
        count = merge_recon_databases(str(tmp_path / "out.db"), [])
        assert count == 0

    def test_merge_multiple_sources(self, tmp_path):
        for i in range(3):
            src = ReconDB(str(tmp_path / f"src{i}.db"))
            src.update_asset(f"host{i}.example.com", confidence=50)

        out_path = str(tmp_path / "out.db")
        sources = [str(tmp_path / f"src{i}.db") for i in range(3)]
        count = merge_recon_databases(out_path, sources)
        assert count == 3


# ── TestExports ───────────────────────────────────────────────────────────────

class TestExports:
    def test_export_csv_creates_file(self, populated_db, tmp_path):
        out = str(tmp_path / "out.csv")
        populated_db.export_csv(out)
        assert os.path.exists(out)

    def test_export_csv_has_correct_headers(self, populated_db, tmp_path):
        out = str(tmp_path / "out.csv")
        populated_db.export_csv(out)
        with open(out, newline="") as f:
            headers = next(csv.reader(f))
        assert "host" in headers
        assert "confidence" in headers
        assert "ip" in headers

    def test_export_csv_row_count(self, populated_db, tmp_path):
        out = str(tmp_path / "out.csv")
        populated_db.export_csv(out)
        with open(out) as f:
            rows = list(csv.reader(f))
        # header + 5 assets
        assert len(rows) == 6

    def test_export_csv_min_conf_filters(self, populated_db, tmp_path):
        out = str(tmp_path / "out.csv")
        populated_db.export_csv(out, min_conf=85)
        with open(out) as f:
            rows = list(csv.reader(f))
        assert len(rows) == 4  # header + 3 high-conf assets

    def test_export_json_creates_file(self, populated_db, tmp_path):
        out = str(tmp_path / "out.json")
        populated_db.export_json(out)
        assert os.path.exists(out)

    def test_export_json_is_valid(self, populated_db, tmp_path):
        out = str(tmp_path / "out.json")
        populated_db.export_json(out)
        with open(out) as f:
            data = json.load(f)
        assert isinstance(data, list)
        assert len(data) == 5

    def test_export_json_min_conf_filters(self, populated_db, tmp_path):
        out = str(tmp_path / "out.json")
        populated_db.export_json(out, min_conf=85)
        with open(out) as f:
            data = json.load(f)
        assert len(data) == 3

    def test_export_json_contains_expected_keys(self, populated_db, tmp_path):
        out = str(tmp_path / "out.json")
        populated_db.export_json(out)
        with open(out) as f:
            data = json.load(f)
        assert "host" in data[0]
        assert "confidence" in data[0]

    def test_generate_html_report_creates_file(self, populated_db, tmp_path):
        populated_db.generate_html_report(0, str(tmp_path))
        assert (tmp_path / "report.html").exists()

    def test_generate_html_report_contains_hosts(self, populated_db, tmp_path):
        populated_db.generate_html_report(0, str(tmp_path))
        content = (tmp_path / "report.html").read_text()
        assert "example.com" in content
        assert "assetTable" in content
        assert "Argus" in content


# ── TestLLMAnalysis ───────────────────────────────────────────────────────────

class TestLLMAnalysis:
    def test_creates_file(self, populated_db, tmp_path):
        args = _fake_args()
        generate_llm_analysis(populated_db, ["example.com"], str(tmp_path), args)
        assert (tmp_path / "llm_analysis.md").exists()

    def test_contains_target_domain(self, populated_db, tmp_path):
        args = _fake_args()
        generate_llm_analysis(populated_db, ["example.com"], str(tmp_path), args)
        content = (tmp_path / "llm_analysis.md").read_text()
        assert "example.com" in content

    def test_contains_asn_section(self, populated_db, tmp_path):
        args = _fake_args()
        generate_llm_analysis(populated_db, ["example.com"], str(tmp_path), args)
        content = (tmp_path / "llm_analysis.md").read_text()
        assert "ASN" in content

    def test_contains_naming_patterns_section(self, populated_db, tmp_path):
        args = _fake_args()
        generate_llm_analysis(populated_db, ["example.com"], str(tmp_path), args)
        content = (tmp_path / "llm_analysis.md").read_text()
        assert "Naming" in content or "Prefix" in content

    def test_empty_db_no_crash(self, tmp_db, tmp_path):
        args = _fake_args()
        generate_llm_analysis(tmp_db, [], str(tmp_path), args)

    def test_env_indicators_detected(self, tmp_db, tmp_path):
        tmp_db.update_asset("dev.example.com", confidence=85)
        tmp_db.update_asset("staging.example.com", confidence=85)
        args = _fake_args()
        generate_llm_analysis(tmp_db, ["example.com"], str(tmp_path), args)
        content = (tmp_path / "llm_analysis.md").read_text()
        assert "dev.example.com" in content or "staging.example.com" in content


# ── TestDeltaReport ───────────────────────────────────────────────────────────

class TestDeltaReport:
    def test_no_changes_prints_message(self, tmp_path, capsys):
        delta = {"new": [], "removed": [], "changed": []}
        generate_delta_report(delta, str(tmp_path), scan_id=1)
        assert not (tmp_path / "delta_report.md").exists()

    def test_creates_md_file_when_changes(self, tmp_path):
        delta = {
            "new": [{"host": "new.example.com", "confidence": 85, "ip": "1.2.3.4", "asn": "AS1"}],
            "removed": [],
            "changed": [],
        }
        generate_delta_report(delta, str(tmp_path), scan_id=2)
        assert (tmp_path / "delta_report.md").exists()

    def test_md_contains_new_assets(self, tmp_path):
        delta = {
            "new": [{"host": "new.example.com", "confidence": 85, "ip": "1.2.3.4", "asn": "AS1"}],
            "removed": [],
            "changed": [],
        }
        generate_delta_report(delta, str(tmp_path), scan_id=3)
        content = (tmp_path / "delta_report.md").read_text()
        assert "new.example.com" in content
        assert "New Assets" in content

    def test_md_contains_removed_assets(self, tmp_path):
        delta = {
            "new": [],
            "removed": [{"host": "gone.example.com", "confidence": 60}],
            "changed": [],
        }
        generate_delta_report(delta, str(tmp_path), scan_id=4)
        content = (tmp_path / "delta_report.md").read_text()
        assert "gone.example.com" in content
        assert "Removed" in content

    def test_md_contains_changed_assets(self, tmp_path):
        delta = {
            "new": [],
            "removed": [],
            "changed": [{"host": "api.example.com", "confidence": 85, "changes": ["ip: 1.1.1.1 → 2.2.2.2"]}],
        }
        generate_delta_report(delta, str(tmp_path), scan_id=5)
        content = (tmp_path / "delta_report.md").read_text()
        assert "api.example.com" in content
        assert "1.1.1.1 → 2.2.2.2" in content


# ── TestLoadConfig ────────────────────────────────────────────────────────────

class TestLoadConfig:
    def test_load_json_config(self, tmp_path):
        cfg = {"domain": ["example.com"], "workers": 16, "verbose": True}
        p = tmp_path / "config.json"
        p.write_text(json.dumps(cfg))
        result = load_config_file(str(p))
        assert result["workers"] == 16
        assert result["verbose"] is True

    def test_load_missing_file_returns_empty(self):
        result = load_config_file("/nonexistent/path/config.yaml")
        assert result == {}

    def test_load_invalid_json_returns_empty(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{invalid json")
        result = load_config_file(str(p))
        assert result == {}

    def test_load_unsupported_extension_returns_empty(self, tmp_path):
        p = tmp_path / "config.toml"
        p.write_text("key = value")
        result = load_config_file(str(p))
        assert result == {}

    def test_apply_preset_passive(self):
        args = _fake_args()
        apply_preset(args, "passive")
        assert args.httpx is False
        assert args.gowitness is False
        assert args.nuclei is False
        assert args.reverse_dns is True
        assert args.geolocate is True

    def test_apply_preset_active(self):
        args = _fake_args()
        apply_preset(args, "active")
        assert args.httpx is True
        assert args.tech_stack_enum is True
        assert args.nuclei is False
        assert args.gowitness is False

    def test_apply_preset_full(self):
        args = _fake_args()
        apply_preset(args, "full")
        assert args.httpx is True
        assert args.gowitness is True
        assert args.nuclei is True
        assert args.reverse_dns is True
        assert args.geolocate is True


# ── TestHelpers ───────────────────────────────────────────────────────────────

class TestFindReconDbFiles:
    def test_finds_file_at_direct_path(self, tmp_path):
        db = tmp_path / "recon.db"
        db.touch()
        result = find_recon_db_files([str(db)])
        assert str(db) in result

    def test_finds_file_in_directory(self, tmp_path):
        db = tmp_path / "recon.db"
        db.touch()
        result = find_recon_db_files([str(tmp_path)])
        assert str(db) in result

    def test_recursive_finds_nested(self, tmp_path):
        nested = tmp_path / "sub" / "scan1"
        nested.mkdir(parents=True)
        db = nested / "recon.db"
        db.touch()
        result = find_recon_db_files([str(tmp_path)], recursive=True)
        assert str(db) in result

    def test_non_recursive_skips_nested(self, tmp_path):
        nested = tmp_path / "sub"
        nested.mkdir()
        db = nested / "recon.db"
        db.touch()
        result = find_recon_db_files([str(tmp_path)], recursive=False)
        assert str(db) not in result

    def test_skips_missing_path(self):
        result = find_recon_db_files(["/nonexistent/path"])
        assert result == []

    def test_returns_sorted(self, tmp_path):
        for name in ("c", "a", "b"):
            d = tmp_path / name
            d.mkdir()
            (d / "recon.db").touch()
        result = find_recon_db_files([str(tmp_path)], recursive=True)
        assert result == sorted(result)

    def test_deduplicates_results(self, tmp_path):
        db = tmp_path / "recon.db"
        db.touch()
        result = find_recon_db_files([str(tmp_path), str(tmp_path)])
        assert result.count(str(db)) == 1


# ── TestWildcardDetection ─────────────────────────────────────────────────────

class TestWildcardDetection:
    def test_returns_ips_when_wildcard_present(self):
        mock_result = MagicMock()
        mock_result.stdout = '{"host":"randomxyz.example.com","a":["1.2.3.4"]}\n'
        mock_result.returncode = 0
        with patch("subprocess.run", return_value=mock_result):
            ips = detect_wildcard_dns("example.com")
        assert "1.2.3.4" in ips

    def test_returns_empty_when_no_wildcard(self):
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.returncode = 1
        with patch("subprocess.run", return_value=mock_result):
            ips = detect_wildcard_dns("example.com")
        assert ips == set()

    def test_returns_empty_on_exception(self):
        with patch("subprocess.run", side_effect=Exception("timeout")):
            ips = detect_wildcard_dns("example.com")
        assert ips == set()

    def test_uses_resolvers_when_provided(self):
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.returncode = 1
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            detect_wildcard_dns("example.com", resolvers="/tmp/resolvers.txt")
            cmd = mock_run.call_args[0][0]
        assert "-r" in cmd
        assert "/tmp/resolvers.txt" in cmd

    def test_probe_uses_random_subdomain(self):
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.returncode = 1
        probes = []
        def capture(cmd, **kwargs):
            probes.append(cmd)
            return mock_result
        with patch("subprocess.run", side_effect=capture):
            detect_wildcard_dns("example.com")
            detect_wildcard_dns("example.com")
        # Both probes should use the target domain but different random prefixes
        assert probes[0] != probes[1]

    def test_multiple_wildcard_ips_returned(self):
        mock_result = MagicMock()
        mock_result.stdout = '{"host":"xyz.example.com","a":["1.2.3.4","5.6.7.8"]}\n'
        mock_result.returncode = 0
        with patch("subprocess.run", return_value=mock_result):
            ips = detect_wildcard_dns("example.com")
        assert ips == {"1.2.3.4", "5.6.7.8"}


# ── TestQuerySummary ──────────────────────────────────────────────────────────

class TestQuerySummary:
    def test_prints_without_error(self, populated_db, capsys):
        populated_db.query_summary(0)
        out = capsys.readouterr().out
        assert "example.com" in out

    def test_empty_db_no_crash(self, tmp_db, capsys):
        tmp_db.query_summary(0)

    def test_min_conf_filters_output(self, populated_db, capsys):
        populated_db.query_summary(85)
        out = capsys.readouterr().out
        assert "old.example.com" not in out


# ── TestEmailAudit ────────────────────────────────────────────────────────────

class TestSpfLookupCount:
    def test_counts_includes(self):
        assert _spf_lookup_count("v=spf1 include:_spf.google.com include:mail.example.com -all") == 2

    def test_counts_a_and_mx(self):
        assert _spf_lookup_count("v=spf1 a mx -all") == 2

    def test_ignores_ip4_ip6(self):
        assert _spf_lookup_count("v=spf1 ip4:1.2.3.4 ip6:::1 -all") == 0

    def test_counts_redirect(self):
        assert _spf_lookup_count("v=spf1 redirect=_spf.example.com") == 1


class TestAnalyzeSpf:
    def test_missing_returns_critical(self):
        with patch("argus._dns_txt", return_value=[]):
            r = _analyze_spf("example.com")
        assert r["present"] is False
        assert r["risk"] == "critical"

    def test_hard_fail_is_pass(self):
        with patch("argus._dns_txt", return_value=["v=spf1 include:_spf.google.com -all"]):
            r = _analyze_spf("example.com")
        assert r["present"] is True
        assert r["risk"] == "pass"
        assert r["issues"] == []

    def test_soft_fail_is_medium(self):
        with patch("argus._dns_txt", return_value=["v=spf1 include:_spf.google.com ~all"]):
            r = _analyze_spf("example.com")
        assert r["risk"] == "medium"
        assert any("~all" in i for i in r["issues"])

    def test_plus_all_is_critical(self):
        with patch("argus._dns_txt", return_value=["v=spf1 +all"]):
            r = _analyze_spf("example.com")
        assert r["risk"] == "critical"

    def test_multiple_spf_records_is_high(self):
        with patch("argus._dns_txt", return_value=["v=spf1 -all", "v=spf1 ~all"]):
            r = _analyze_spf("example.com")
        assert r["risk"] == "high"
        assert any("Multiple" in i for i in r["issues"])

    def test_lookup_limit_exceeded(self):
        includes = " ".join(f"include:s{i}.example.com" for i in range(11))
        with patch("argus._dns_txt", return_value=[f"v=spf1 {includes} -all"]):
            r = _analyze_spf("example.com")
        assert r["lookup_count"] == 11
        assert r["risk"] == "high"


class TestAnalyzeDmarc:
    def test_missing_returns_critical(self):
        with patch("argus._dns_txt", return_value=[]):
            r = _analyze_dmarc("example.com")
        assert r["present"] is False
        assert r["risk"] == "critical"

    def test_p_none_is_high(self):
        with patch("argus._dns_txt", return_value=["v=DMARC1; p=none; rua=mailto:dmarc@example.com"]):
            r = _analyze_dmarc("example.com")
        assert r["policy"] == "none"
        assert r["risk"] == "high"

    def test_p_quarantine_is_medium(self):
        with patch("argus._dns_txt", return_value=["v=DMARC1; p=quarantine; pct=100; rua=mailto:d@x.com"]):
            r = _analyze_dmarc("example.com")
        assert r["policy"] == "quarantine"
        assert r["risk"] == "medium"

    def test_p_reject_no_issues_is_pass(self):
        with patch("argus._dns_txt", return_value=["v=DMARC1; p=reject; pct=100; rua=mailto:d@x.com; sp=reject"]):
            r = _analyze_dmarc("example.com")
        assert r["policy"] == "reject"
        assert r["risk"] == "pass"
        assert r["issues"] == []

    def test_pct_less_than_100(self):
        with patch("argus._dns_txt", return_value=["v=DMARC1; p=reject; pct=50"]):
            r = _analyze_dmarc("example.com")
        assert r["pct"] == 50
        assert any("pct=50" in i for i in r["issues"])

    def test_no_reporting_flagged(self):
        with patch("argus._dns_txt", return_value=["v=DMARC1; p=reject; pct=100"]):
            r = _analyze_dmarc("example.com")
        assert any("reporting" in i.lower() for i in r["issues"])


class TestEstimateRsaBits:
    def test_none_returns_none(self):
        assert _estimate_rsa_bits("") is None

    def test_short_key_is_1024(self):
        # ~180 byte key → 1024-bit
        import base64 as b64
        fake_der = b"x" * 180
        p = b64.b64encode(fake_der).decode()
        assert _estimate_rsa_bits(p) == 1024

    def test_long_key_is_2048(self):
        import base64 as b64
        fake_der = b"x" * 350
        p = b64.b64encode(fake_der).decode()
        assert _estimate_rsa_bits(p) == 2048


class TestEmailRiskScore:
    def test_no_spf_is_critical(self):
        spf   = {"present": False, "risk": "critical"}
        dmarc = {"present": True,  "risk": "pass", "policy": "reject"}
        assert _email_risk_score(spf, dmarc, []) == "CRITICAL"

    def test_dmarc_none_is_high(self):
        spf   = {"present": True, "risk": "pass"}
        dmarc = {"present": True, "risk": "high", "policy": "none"}
        assert _email_risk_score(spf, dmarc, []) == "HIGH"

    def test_soft_fail_is_medium(self):
        spf   = {"present": True, "risk": "medium"}
        dmarc = {"present": True, "risk": "pass", "policy": "reject"}
        assert _email_risk_score(spf, dmarc, []) == "MEDIUM"

    def test_full_protection_is_pass(self):
        spf   = {"present": True, "risk": "pass"}
        dmarc = {"present": True, "risk": "pass", "policy": "reject"}
        dkim  = [{"selector": "google", "risk": "pass", "revoked": False, "key_bits": 2048}]
        assert _email_risk_score(spf, dmarc, dkim) == "PASS"

    def test_weak_dkim_key_is_medium(self):
        spf   = {"present": True, "risk": "pass"}
        dmarc = {"present": True, "risk": "pass", "policy": "reject"}
        dkim  = [{"selector": "mail", "risk": "medium", "revoked": False, "key_bits": 1024}]
        assert _email_risk_score(spf, dmarc, dkim) == "MEDIUM"


class TestIdentifyMxProvider:
    def test_google_workspace(self):
        assert _identify_mx_provider("aspmx.l.google.com") == "Google Workspace"

    def test_microsoft_365(self):
        assert _identify_mx_provider("contoso-com.mail.protection.outlook.com") == "Microsoft 365"

    def test_proofpoint(self):
        assert _identify_mx_provider("mail.pphosted.com") == "Proofpoint"

    def test_unknown_returns_none(self):
        assert _identify_mx_provider("mail.unknown-provider.net") is None


# ── TestClassifyCname ─────────────────────────────────────────────────────────

class TestClassifyCname:
    # Cloud storage — label, is_storage=True, is_takeover=False, bucket extracted
    def test_s3_bucket(self):
        label, is_storage, is_takeover, bucket = _classify_cname("mybucket.s3.amazonaws.com")
        assert label == "AWS S3"
        assert is_storage is True
        assert is_takeover is False
        assert bucket == "mybucket"

    def test_azure_blob(self):
        label, is_storage, is_takeover, bucket = _classify_cname("myaccount.blob.core.windows.net")
        assert label == "Azure Blob"
        assert is_storage is True
        assert is_takeover is False
        assert bucket == "myaccount"

    def test_gcp_storage(self):
        label, is_storage, is_takeover, bucket = _classify_cname("mybucket.storage.googleapis.com")
        assert label == "GCP Storage"
        assert is_storage is True
        assert is_takeover is False
        assert bucket == "mybucket"

    def test_s3_website(self):
        label, is_storage, is_takeover, bucket = _classify_cname("mybucket.s3-website-us-east-1.amazonaws.com")
        assert label is not None
        assert is_storage is True

    # Takeover-prone services — is_takeover=True
    def test_github_pages_is_takeover_prone(self):
        label, is_storage, is_takeover, bucket = _classify_cname("hacker0x01.github.io")
        assert label == "GitHub Pages"
        assert is_storage is False
        assert is_takeover is True
        assert bucket is None

    def test_netlify_is_takeover_prone(self):
        _, _, is_takeover, _ = _classify_cname("mysite.netlify.app")
        assert is_takeover is True

    def test_vercel_is_takeover_prone(self):
        _, _, is_takeover, _ = _classify_cname("myapp.vercel.app")
        assert is_takeover is True

    def test_heroku_is_takeover_prone(self):
        _, _, is_takeover, _ = _classify_cname("myapp.herokudns.com")
        assert is_takeover is True

    def test_surge_is_takeover_prone(self):
        _, _, is_takeover, _ = _classify_cname("mysite.surge.sh")
        assert is_takeover is True

    def test_azure_webapp_is_takeover_prone(self):
        _, _, is_takeover, _ = _classify_cname("myapp.azurewebsites.net")
        assert is_takeover is True

    # CDN services — not takeover prone
    def test_cloudfront_not_takeover_prone(self):
        label, is_storage, is_takeover, bucket = _classify_cname("d3rxkn2g2bbsjp.cloudfront.net")
        assert label == "CloudFront CDN"
        assert is_takeover is False

    def test_fastly_not_takeover_prone(self):
        _, _, is_takeover, _ = _classify_cname("something.fastly.net")
        assert is_takeover is False

    def test_freshdesk_unrecognised(self):
        label, is_storage, is_takeover, bucket = _classify_cname("abc123.freshdesk.com")
        assert label is None
        assert is_storage is False
        assert is_takeover is False
        assert bucket is None

    # Case insensitivity
    def test_case_insensitive(self):
        label, is_storage, is_takeover, bucket = _classify_cname("MYBUCKET.S3.AMAZONAWS.COM")
        assert label == "AWS S3"
        assert bucket == "mybucket"

    # Trailing dot (common in DNS)
    def test_trailing_dot_stripped(self):
        label, is_storage, is_takeover, bucket = _classify_cname("mybucket.s3.amazonaws.com.")
        assert label == "AWS S3"
        assert bucket == "mybucket"

    # DB schema has cname column
    def test_cname_column_exists(self, tmp_db):
        with tmp_db._connection() as conn:
            cols = [r[1] for r in conn.execute("PRAGMA table_info(assets)").fetchall()]
        assert "cname" in cols

    # update_asset stores cname
    def test_cname_stored_on_asset(self, tmp_db):
        tmp_db.update_asset("files.example.com", cname="files.s3.amazonaws.com")
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT cname FROM assets WHERE host='files.example.com'").fetchone()
        assert row[0] == "files.s3.amazonaws.com"


class TestCheckResolves:
    def test_resolves_real_domain(self):
        # Use localhost which always resolves
        assert _check_resolves("localhost") is True

    def test_nxdomain_returns_false(self):
        assert _check_resolves("this-domain-absolutely-does-not-exist-xyzzy123.com") is False

    def test_trailing_dot_handled(self):
        assert _check_resolves("localhost.") is True


class TestTakeoverDetection:
    def test_takeover_vuln_stored_on_asset(self, tmp_db):
        tmp_db.update_asset("sub.example.com",
                            cname="unclaimed.github.io",
                            vulns=["takeover-risk:github-pages"])
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT vulns FROM assets WHERE host='sub.example.com'").fetchone()
        assert "takeover-risk" in row[0]

    def test_nxdomain_variant_stored(self, tmp_db):
        tmp_db.update_asset("sub.example.com",
                            cname="gone.netlify.app",
                            vulns=["takeover-risk:netlify(nxdomain)"])
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT vulns FROM assets WHERE host='sub.example.com'").fetchone()
        assert "nxdomain" in row[0]

    def test_confirmed_takeover_stored(self, tmp_db):
        tmp_db.update_asset("sub.example.com",
                            vulns=["subdomain-takeover:github-pages-takeover(high)"])
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT vulns FROM assets WHERE host='sub.example.com'").fetchone()
        assert "subdomain-takeover:" in row[0]

    def test_vulns_accumulate(self, tmp_db):
        tmp_db.update_asset("sub.example.com", vulns=["takeover-risk:netlify"])
        tmp_db.update_asset("sub.example.com", vulns=["subdomain-takeover:netlify-takeover(high)"])
        with tmp_db._connection() as conn:
            row = conn.execute("SELECT vulns FROM assets WHERE host='sub.example.com'").fetchone()
        assert "takeover-risk" in row[0]
        assert "subdomain-takeover:" in row[0]


# ── TestPtrConfidence ─────────────────────────────────────────────────────────

class TestPtrConfidence:
    SEEDS = {"hackerone.com"}

    # Hard skip cases
    def test_skip_root_server(self):
        skip, _ = _ptr_confidence("a.root-servers.net", self.SEEDS)
        assert skip is True

    def test_skip_all_root_servers(self):
        for host in ("b.root-servers.net", "m.root-servers.net", "j.root-servers.net"):
            skip, _ = _ptr_confidence(host, self.SEEDS)
            assert skip is True, f"{host} should be skipped"

    def test_skip_in_addr_arpa(self):
        skip, _ = _ptr_confidence("1.0.0.127.in-addr.arpa", self.SEEDS)
        assert skip is True

    # Related to seed domain → confidence 50
    def test_seed_domain_itself(self):
        skip, conf = _ptr_confidence("hackerone.com", self.SEEDS)
        assert skip is False
        assert conf == 50

    def test_subdomain_of_seed(self):
        skip, conf = _ptr_confidence("api.hackerone.com", self.SEEDS)
        assert skip is False
        assert conf == 50

    def test_deep_subdomain_of_seed(self):
        skip, conf = _ptr_confidence("mta-sts.managed.hackerone.com", self.SEEDS)
        assert skip is False
        assert conf == 50

    # Generic infra PTRs → confidence 25
    def test_aws_ec2_ptr(self):
        skip, conf = _ptr_confidence("ec2-3-150-65-250.us-east-2.compute.amazonaws.com", self.SEEDS)
        assert skip is False
        assert conf == 25

    def test_cloudfront_ptr(self):
        skip, conf = _ptr_confidence("server-65-9-46-44.arn52.r.cloudfront.net", self.SEEDS)
        assert skip is False
        assert conf == 25

    def test_github_cdn_ptr(self):
        skip, conf = _ptr_confidence("cdn-185-199-108-153.github.com", self.SEEDS)
        assert skip is False
        assert conf == 25

    def test_googleusercontent_ptr(self):
        skip, conf = _ptr_confidence("123.compute.googleusercontent.com", self.SEEDS)
        assert skip is False
        assert conf == 25

    def test_fastly_ptr(self):
        skip, conf = _ptr_confidence("prod.fastly.net", self.SEEDS)
        assert skip is False
        assert conf == 25

    # Unknown PTR unrelated to seeds → confidence 50 (store, investigate)
    def test_unknown_unrelated_ptr(self):
        skip, conf = _ptr_confidence("somehost.unrelated-isp.net", self.SEEDS)
        assert skip is False
        assert conf == 50

    # Case insensitivity
    def test_case_insensitive_skip(self):
        skip, _ = _ptr_confidence("A.ROOT-SERVERS.NET", self.SEEDS)
        assert skip is True

    def test_case_insensitive_seed_match(self):
        skip, conf = _ptr_confidence("API.HACKERONE.COM", self.SEEDS)
        assert skip is False
        assert conf == 50

    # Multiple seed domains
    def test_multiple_seeds_second_match(self):
        seeds = {"hackerone.com", "bugcrowd.com"}
        skip, conf = _ptr_confidence("api.bugcrowd.com", seeds)
        assert skip is False
        assert conf == 50

    # Partial match should not trigger (e.g. "fakehackerone.com")
    def test_no_partial_seed_match(self):
        skip, conf = _ptr_confidence("fakehackerone.com", self.SEEDS)
        assert skip is False
        assert conf == 50  # unknown, not infra, not seed — stored at 50


# ── TestAPIEnrichment ─────────────────────────────────────────────────────────

def _mock_urlopen(response_body: str, status: int = 200):
    """Return a context-manager mock for urllib.request.urlopen."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = response_body.encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_resp.status = status
    return mock_resp


class TestQueryShodan:
    def test_returns_fqdns(self):
        body = json.dumps({"domain": "example.com", "subdomains": ["www", "api", "mail"]})
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(body)):
            result = query_shodan("example.com", "fake-key")
        assert result == {"www.example.com", "api.example.com", "mail.example.com"}

    def test_empty_subdomains(self):
        body = json.dumps({"domain": "example.com", "subdomains": []})
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(body)):
            result = query_shodan("example.com", "fake-key")
        assert result == set()

    def test_401_prints_warning(self, capsys):
        import urllib.error
        with patch("urllib.request.urlopen", side_effect=urllib.error.HTTPError(None, 401, "Unauthorized", {}, None)):
            result = query_shodan("example.com", "bad-key")
        assert result == set()
        assert "invalid" in capsys.readouterr().out.lower()

    def test_network_exception_returns_empty(self):
        with patch("urllib.request.urlopen", side_effect=Exception("timeout")):
            result = query_shodan("example.com", "key")
        assert result == set()

    def test_no_output_on_success(self, capsys):
        body = json.dumps({"domain": "example.com", "subdomains": ["www"]})
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(body)):
            query_shodan("example.com", "key")
        assert capsys.readouterr().out == ""

    def test_fqdns_are_lowercase(self):
        body = json.dumps({"domain": "Example.COM", "subdomains": ["WWW"]})
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(body)):
            result = query_shodan("Example.COM", "key")
        for host in result:
            assert host == host.lower()


class TestQueryCensys:
    def test_bearer_token_auth_header(self):
        body = json.dumps({"result": {"hits": []}})
        captured = []
        def capture(req, **kwargs):
            captured.append(req.get_header("Authorization"))
            return _mock_urlopen(body)
        with patch("urllib.request.urlopen", side_effect=capture):
            query_censys("example.com", api_token="mytoken")
        assert captured[0] == "Bearer mytoken"

    def test_basic_auth_header(self):
        import base64 as b64
        body = json.dumps({"result": {"hits": []}})
        captured = []
        def capture(req, **kwargs):
            captured.append(req.get_header("Authorization"))
            return _mock_urlopen(body)
        with patch("urllib.request.urlopen", side_effect=capture):
            query_censys("example.com", api_id="myid", api_secret="mysecret")
        expected = "Basic " + b64.b64encode(b"myid:mysecret").decode()
        assert captured[0] == expected

    def test_bearer_token_returns_matching_fqdns(self):
        body = json.dumps({
            "result": {
                "hits": [
                    {"parsed.names": ["www.example.com", "api.example.com", "unrelated.net"]}
                ]
            }
        })
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(body)):
            result = query_censys("example.com", api_token="tok")
        assert "www.example.com" in result
        assert "api.example.com" in result
        assert "unrelated.net" not in result

    def test_basic_auth_returns_matching_fqdns(self):
        body = json.dumps({
            "result": {"hits": [{"parsed.names": ["mail.example.com"]}]}
        })
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(body)):
            result = query_censys("example.com", api_id="id123", api_secret="secret456")
        assert "mail.example.com" in result

    def test_no_credentials_returns_empty(self):
        result = query_censys("example.com")
        assert result == set()

    def test_app_id_preferred_when_both_provided(self):
        """App ID + Secret takes priority because bearer token cannot do cert search."""
        import base64 as b64
        body = json.dumps({"result": {"hits": []}})
        captured = []
        def capture(req, **kwargs):
            captured.append(req.get_header("Authorization"))
            return _mock_urlopen(body)
        with patch("urllib.request.urlopen", side_effect=capture):
            query_censys("example.com", api_token="tok", api_id="id", api_secret="sec")
        assert captured[0].startswith("Basic ")

    def test_filters_non_matching_domains(self):
        body = json.dumps({"result": {"hits": [{"parsed.names": ["other.org"]}]}})
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(body)):
            result = query_censys("example.com", api_token="tok")
        assert result == set()

    def test_strips_wildcard_prefix(self):
        body = json.dumps({"result": {"hits": [{"parsed.names": ["*.example.com"]}]}})
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(body)):
            result = query_censys("example.com", api_token="tok")
        assert "example.com" in result
        assert "*.example.com" not in result

    def test_401_prints_warning(self, capsys):
        import urllib.error
        with patch("urllib.request.urlopen", side_effect=urllib.error.HTTPError(None, 401, "Unauthorized", {}, None)):
            result = query_censys("example.com", api_token="bad")
        assert result == set()
        assert "lookup-only" in capsys.readouterr().out.lower()

    def test_401_basic_auth_prints_warning(self, capsys):
        import urllib.error
        with patch("urllib.request.urlopen", side_effect=urllib.error.HTTPError(None, 401, "Unauthorized", {}, None)):
            result = query_censys("example.com", api_id="bad", api_secret="creds")
        assert result == set()
        assert "invalid" in capsys.readouterr().out.lower()

    def test_network_exception_returns_empty(self):
        with patch("urllib.request.urlopen", side_effect=Exception("timeout")):
            result = query_censys("example.com", api_token="tok")
        assert result == set()

    def test_empty_hits_returns_empty(self):
        body = json.dumps({"result": {"hits": []}})
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(body)):
            result = query_censys("example.com", api_token="tok")
        assert result == set()


class TestQueryVirusTotal:
    def test_returns_subdomains(self):
        body = json.dumps({
            "data": [
                {"id": "www.example.com", "type": "domain"},
                {"id": "api.example.com", "type": "domain"},
            ]
        })
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(body)):
            result = query_virustotal("example.com", "fake-key")
        assert result == {"www.example.com", "api.example.com"}

    def test_empty_data_returns_empty(self):
        body = json.dumps({"data": []})
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(body)):
            result = query_virustotal("example.com", "key")
        assert result == set()

    def test_401_prints_warning(self, capsys):
        import urllib.error
        with patch("urllib.request.urlopen", side_effect=urllib.error.HTTPError(None, 401, "Unauthorized", {}, None)):
            result = query_virustotal("example.com", "bad-key")
        assert result == set()
        assert "invalid" in capsys.readouterr().out.lower()

    def test_network_exception_returns_empty(self):
        with patch("urllib.request.urlopen", side_effect=Exception("timeout")):
            result = query_virustotal("example.com", "key")
        assert result == set()

    def test_no_output_on_success(self, capsys):
        body = json.dumps({"data": [{"id": "sub.example.com"}]})
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(body)):
            query_virustotal("example.com", "key")
        assert capsys.readouterr().out == ""

    def test_results_are_lowercase(self):
        body = json.dumps({"data": [{"id": "SUB.EXAMPLE.COM"}]})
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(body)):
            result = query_virustotal("example.com", "key")
        for host in result:
            assert host == host.lower()


class TestRunApiEnrichment:
    def test_no_keys_returns_empty(self):
        args = _fake_args()
        with patch.dict("os.environ", {}, clear=True):
            result = run_api_enrichment(["example.com"], args)
        assert result == set()

    def test_shodan_key_from_env(self, capsys):
        args = _fake_args()
        body = json.dumps({"domain": "example.com", "subdomains": ["api"]})
        with patch.dict("os.environ", {"SHODAN_API_KEY": "testkey"}):
            with patch("urllib.request.urlopen", return_value=_mock_urlopen(body)):
                result = run_api_enrichment(["example.com"], args)
        assert "api.example.com" in result

    def test_shodan_key_from_args(self, capsys):
        args = _fake_args()
        args.shodan_api_key = "argkey"
        body = json.dumps({"domain": "example.com", "subdomains": ["dev"]})
        with patch.dict("os.environ", {}, clear=True):
            with patch("urllib.request.urlopen", return_value=_mock_urlopen(body)):
                result = run_api_enrichment(["example.com"], args)
        assert "dev.example.com" in result

    def test_virustotal_key_from_env(self):
        args = _fake_args()
        body = json.dumps({"data": [{"id": "mail.example.com"}]})
        with patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "vtkey"}):
            with patch("urllib.request.urlopen", return_value=_mock_urlopen(body)):
                result = run_api_enrichment(["example.com"], args)
        assert "mail.example.com" in result

    def test_results_aggregated_across_domains(self):
        args = _fake_args()
        args.shodan_api_key = "key"
        responses = [
            json.dumps({"domain": "example.com", "subdomains": ["api"]}),
            json.dumps({"domain": "partner.com",  "subdomains": ["www"]}),
        ]
        side_effects = [_mock_urlopen(r) for r in responses]
        with patch.dict("os.environ", {}, clear=True):
            with patch("urllib.request.urlopen", side_effect=side_effects):
                result = run_api_enrichment(["example.com", "partner.com"], args)
        assert "api.example.com" in result
        assert "www.partner.com" in result

    def test_always_prints_per_service_count(self, capsys):
        args = _fake_args()
        args.shodan_api_key = "key"
        args.virustotal_api_key = "vtkey"
        bodies = [
            json.dumps({"domain": "example.com", "subdomains": ["api", "dev"]}),
            json.dumps({"data": [{"id": "mail.example.com"}]}),
        ]
        side_effects = [_mock_urlopen(b) for b in bodies]
        with patch.dict("os.environ", {}, clear=True):
            with patch("urllib.request.urlopen", side_effect=side_effects):
                run_api_enrichment(["example.com"], args)
        out = capsys.readouterr().out
        assert "Shodan: 2 entries added to seeds" in out
        assert "VirusTotal: 1 entries added to seeds" in out

    def test_prints_zero_count_when_no_results(self, capsys):
        args = _fake_args()
        args.shodan_api_key = "key"
        body = json.dumps({"domain": "example.com", "subdomains": []})
        with patch.dict("os.environ", {}, clear=True):
            with patch("urllib.request.urlopen", return_value=_mock_urlopen(body)):
                run_api_enrichment(["example.com"], args)
        out = capsys.readouterr().out
        assert "Shodan: 0 entries added to seeds" in out

    def test_env_takes_precedence_over_args(self):
        args = _fake_args()
        args.shodan_api_key = "args-key"
        body = json.dumps({"domain": "example.com", "subdomains": ["test"]})
        captured_keys = []
        original_urlopen = __import__("urllib.request", fromlist=["urlopen"]).urlopen

        def capture_req(req, **kwargs):
            captured_keys.append(req.full_url)
            return _mock_urlopen(body)

        with patch.dict("os.environ", {"SHODAN_API_KEY": "env-key"}):
            with patch("urllib.request.urlopen", side_effect=capture_req):
                run_api_enrichment(["example.com"], args)
        assert any("env-key" in url for url in captured_keys)
