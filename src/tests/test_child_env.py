"""Tests for the clean child-process environment."""

import shutil
import subprocess
import sys

import pytest

from runner.child_env import STRIPPED_VARS, child_env, child_env_with_removed, describe

ROS_LIKE = {
    "PATH": "/usr/bin",
    "HOME": "/home/x",
    "PYTHONPATH": "/opt/ros/jazzy/lib/python3.12/site-packages",
    "LD_LIBRARY_PATH": "/opt/ros/jazzy/lib",
    "ROS_DISTRO": "jazzy",
}


def test_strips_pythonpath_and_ld_library_path():
    env, removed = child_env_with_removed(ROS_LIKE)
    assert "PYTHONPATH" not in env and "LD_LIBRARY_PATH" not in env
    assert removed == ["LD_LIBRARY_PATH", "PYTHONPATH"]
    assert env["PATH"] == "/usr/bin" and env["ROS_DISTRO"] == "jazzy"


def test_does_not_modify_base():
    base = dict(ROS_LIKE)
    child_env(base)
    assert base == ROS_LIKE


def test_nothing_to_remove():
    env, removed = child_env_with_removed({"PATH": "/usr/bin"})
    assert env == {"PATH": "/usr/bin"} and removed == []
    assert "none were set" in describe(removed)


def test_defaults_to_os_environ(monkeypatch):
    monkeypatch.setenv("PYTHONPATH", "/leak")
    assert "PYTHONPATH" not in child_env()


def test_describe_lists_what_was_present():
    text = describe(["PYTHONPATH"])
    assert all(v in text for v in STRIPPED_VARS)
    assert "present in parent: PYTHONPATH" in text


def test_real_child_does_not_see_pythonpath(monkeypatch):
    monkeypatch.setenv("PYTHONPATH", "/leak")
    monkeypatch.setenv("LD_LIBRARY_PATH", "/leak")
    out = subprocess.run(
        [sys.executable, "-c",
         "import os; print(os.environ.get('PYTHONPATH'), os.environ.get('LD_LIBRARY_PATH'))"],
        env=child_env(), capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "None None"


@pytest.mark.skipif(shutil.which("curl") is None, reason="curl not installed")
def test_curl_record_notes_stripped_vars(monkeypatch, tmp_path):
    import socket

    from runner import client_curl as cc

    monkeypatch.setenv("PYTHONPATH", "/leak")
    monkeypatch.delenv("LD_LIBRARY_PATH", raising=False)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    _, record = cc.run(1, None, None, tmp_path, port=port)
    assert "present in parent: PYTHONPATH" in record["environment"]["child_env"]
