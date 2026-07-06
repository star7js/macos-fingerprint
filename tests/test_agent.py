"""Tests for the headless agent: history chaining, tamper detection, plist gen."""

import json

from macos_fingerprint.audit import agent as ar


def test_append_and_load_roundtrip(tmp_path):
    hf = str(tmp_path / "history.jsonl")
    r1 = ar.append_history(ar.build_record("t1", {"grade": "A"}, []), hf)
    r2 = ar.append_history(ar.build_record("t2", {"grade": "B"}, ["kexts"]), hf)
    history = ar.load_history(hf)
    assert [h["timestamp"] for h in history] == ["t1", "t2"]
    assert r1["prev"] == ar.GENESIS
    assert r2["prev"] == r1["hash"]  # chained to the previous record


def test_load_missing_history_is_empty(tmp_path):
    assert ar.load_history(str(tmp_path / "nope.jsonl")) == []


def test_verify_intact_chain(tmp_path):
    hf = str(tmp_path / "history.jsonl")
    ar.append_history(ar.build_record("t1", {"grade": "A"}, []), hf)
    ar.append_history(ar.build_record("t2", {"grade": "A"}, []), hf)
    ok, index = ar.verify_history_chain(hf)
    assert ok is True and index is None


def test_verify_detects_edited_record(tmp_path):
    hf = str(tmp_path / "history.jsonl")
    ar.append_history(ar.build_record("t1", {"grade": "F"}, []), hf)
    ar.append_history(ar.build_record("t2", {"grade": "A"}, []), hf)
    lines = open(hf).read().splitlines()
    rec = json.loads(lines[0])
    rec["audit"]["grade"] = "A"  # silent edit, hash not recomputed
    lines[0] = json.dumps(rec, sort_keys=True)
    open(hf, "w").write("\n".join(lines) + "\n")
    ok, index = ar.verify_history_chain(hf)
    assert ok is False and index == 0


def test_verify_detects_deleted_record(tmp_path):
    hf = str(tmp_path / "history.jsonl")
    ar.append_history(ar.build_record("t1", {"grade": "A"}, []), hf)
    ar.append_history(ar.build_record("t2", {"grade": "A"}, []), hf)
    ar.append_history(ar.build_record("t3", {"grade": "A"}, []), hf)
    lines = open(hf).read().splitlines()
    del lines[1]  # remove the middle record; breaks the prev-link at the next
    open(hf, "w").write("\n".join(lines) + "\n")
    ok, index = ar.verify_history_chain(hf)
    assert ok is False and index == 1


def test_build_record_drift_flags():
    none = ar.build_record("t", {"grade": "A"}, None)
    assert none["drift"] == {"changed": False, "sections": []}
    empty = ar.build_record("t", {"grade": "A"}, [])
    assert empty["drift"] == {"changed": False, "sections": []}
    changed = ar.build_record("t", {"grade": "A"}, ["kexts", "apps"])
    assert changed["drift"]["changed"] is True
    assert changed["drift"]["sections"] == ["apps", "kexts"]  # sorted


def test_build_launchd_plist_contains_schedule_and_args():
    plist = ar.build_launchd_plist(
        ["/usr/bin/python3", "mf.py", "agent", "run"],
        interval_seconds=43200,
        label="com.test.agent",
    )
    assert "com.test.agent" in plist
    assert "<integer>43200</integer>" in plist
    assert "<string>agent</string>" in plist
    assert plist.startswith("<?xml")
