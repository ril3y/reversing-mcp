"""
Tests for common.py — discovery, resolve_instance, call_instance.

These exercise the shared helpers all MCP servers route through.  Behaviors
under test:

  * dead-PID registration files are pruned on read
  * substring matching across multiple name keys
  * call_instance returns a usable error dict when no instances are present
  * call_instance unlinks the registration file when the bridge refuses
    a connection (so the next call doesn't keep trying a dead bridge)
"""

from __future__ import annotations

import json
import os

import common
from conftest import FakeBridge, bridge_registered, write_registration


# ---------------------------------------------------------------------------
# discover_instances
# ---------------------------------------------------------------------------

def test_discover_returns_empty_when_dir_missing(tmp_path):
    missing = str(tmp_path / "does_not_exist")
    assert common.discover_instances(missing) == []


def test_discover_returns_empty_for_empty_dir(reg_dir):
    assert common.discover_instances(reg_dir) == []


def test_discover_skips_non_json_files(reg_dir):
    open(os.path.join(reg_dir, "README"), "w").write("not json")
    assert common.discover_instances(reg_dir) == []


def test_discover_prunes_dead_pid(reg_dir):
    # PID 999999 is overwhelmingly unlikely to be alive on a dev box.
    # common.py uses a non-signalling check (OpenProcess on Windows,
    # os.kill(pid,0) on POSIX) to decide whether to prune.
    path = os.path.join(reg_dir, "999999.json")
    with open(path, "w") as f:
        json.dump({"pid": 999999, "port": 1234, "name": "x"}, f)

    result = common.discover_instances(reg_dir)
    assert result == []
    assert not os.path.exists(path), "dead-PID file should be unlinked"


def test_pid_alive_does_not_signal_live_target(reg_dir):
    """Regression: on Windows, os.kill(pid, 0) can actually terminate the
    process. discover_instances() must never signal the target — it should
    use a read-only existence check (OpenProcess with PROCESS_QUERY_LIMITED_
    INFORMATION on Windows). We verify by spawning a sleep subprocess,
    registering it, calling discover, then asserting it's STILL alive.
    """
    import subprocess
    import sys as _sys
    import time

    # Cross-platform "sleep for 5s" subprocess that won't take input
    proc = subprocess.Popen(
        [_sys.executable, "-c", "import time; time.sleep(5)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        write_registration(reg_dir, port=4242, pid=proc.pid)
        instances = common.discover_instances(reg_dir)
        assert len(instances) == 1
        assert instances[0]["pid"] == proc.pid
        # Give the OS a moment, then confirm the process is STILL alive.
        time.sleep(0.1)
        assert proc.poll() is None, \
            "discover_instances must not signal the live target process"
    finally:
        proc.terminate()
        proc.wait(timeout=3)


def test_discover_keeps_live_pid(reg_dir):
    write_registration(reg_dir, port=1234)  # our own PID — alive
    assert len(common.discover_instances(reg_dir)) == 1


def test_discover_ignores_corrupt_json(reg_dir):
    open(os.path.join(reg_dir, "junk.json"), "w").write("{not valid json")
    assert common.discover_instances(reg_dir) == []


# ---------------------------------------------------------------------------
# resolve_instance
# ---------------------------------------------------------------------------

def test_resolve_returns_first_when_target_omitted(reg_dir):
    write_registration(reg_dir, port=4001, name="alpha")
    inst = common.resolve_instance(reg_dir)
    assert inst is not None
    assert inst["port"] == 4001


def test_resolve_substring_matches_across_name_keys(reg_dir, tmp_path):
    # Write two registrations differing only in their "idb" field.
    p1 = os.path.join(reg_dir, "111111.json")
    p2 = os.path.join(reg_dir, str(os.getpid()) + ".json")
    json.dump({"pid": os.getpid(), "port": 5001, "idb": "firmware.bin",
               "idb_path": "/tmp/firmware.bin"}, open(p1, "w"))
    json.dump({"pid": os.getpid(), "port": 5002, "idb": "loader.elf",
               "idb_path": "/tmp/loader.elf"}, open(p2, "w"))

    found = common.resolve_instance(reg_dir, target="loader",
                                    name_keys=("idb", "idb_path"))
    assert found is not None and found["port"] == 5002


def test_resolve_returns_none_when_no_match(reg_dir):
    write_registration(reg_dir, port=4001, name="alpha")
    assert common.resolve_instance(reg_dir, target="zzz") is None


# ---------------------------------------------------------------------------
# call_instance
# ---------------------------------------------------------------------------

def test_call_instance_no_bridges_returns_error_dict(reg_dir):
    r = common.call_instance(reg_dir, "/info", tool_name="Demo")
    assert "error" in r and "No Demo instances" in r["error"]


def test_call_instance_target_unmatched_lists_available(reg_dir):
    write_registration(reg_dir, port=4001, name="alpha")
    r = common.call_instance(reg_dir, "/info", target="missing",
                             tool_name="Demo")
    assert "error" in r and "Available" in r["error"]


def test_call_instance_get(fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/info", lambda m, b: (200, {"name": "ok"}))
    with bridge_registered(fake_bridge, reg_dir):
        r = common.call_instance(reg_dir, "/info", tool_name="Demo")
    assert r == {"name": "ok"}


def test_call_instance_post_sends_body(fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/echo", lambda m, b: (200, {"got": b}))
    with bridge_registered(fake_bridge, reg_dir):
        r = common.call_instance(reg_dir, "/echo", body={"address": "0x100"},
                                 tool_name="Demo")
    assert r == {"got": {"address": "0x100"}}
    # And the fake recorded a POST
    method = next(m for (p, m, _) in fake_bridge.calls if p == "/echo")
    assert method == "POST"


def test_call_instance_unlinks_registration_on_connect_error(reg_dir):
    # Register a bridge on a port nothing is listening on.  call_instance
    # should treat a ConnectError as "bridge died" and delete the file so
    # subsequent calls don't keep hitting it.
    pid = write_registration(reg_dir, port=1, name="ghost")  # port 1 = closed
    reg_file = os.path.join(reg_dir, f"{pid}.json")
    assert os.path.exists(reg_file)

    r = common.call_instance(reg_dir, "/info", tool_name="Demo")

    assert "error" in r and "not responding" in r["error"]
    assert not os.path.exists(reg_file), \
        "registration file should be removed after ConnectError"


# ---------------------------------------------------------------------------
# list_instances_text
# ---------------------------------------------------------------------------

def test_list_instances_text_empty(reg_dir):
    assert "No active Demo" in common.list_instances_text(reg_dir, "Demo")


def test_list_instances_text_renders_each_entry(reg_dir):
    write_registration(reg_dir, port=4001, name="thing-one")
    out = common.list_instances_text(reg_dir, "Demo", name_key="name")
    assert "thing-one" in out
    assert "port:4001" in out
