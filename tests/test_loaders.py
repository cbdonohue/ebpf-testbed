#!/usr/bin/env python3
"""
test_loaders.py — Smoke-test that Python loader scripts import cleanly.

Validates:
  - Each loader module can be imported without errors
  - Required top-level names (main, BPF_SRC) are present
  - BPF_SRC paths resolve to existing files

Requires: Python 3.6+ (no BCC or root needed for these checks).
"""

import os
import sys
import importlib.util
import unittest

REPO_ROOT   = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOADER_INFO = [
    ("hello",           "src/hello_world/hello.py"),
    ("packet_counter",  "src/packet_counter/packet_counter.py"),
    ("syscall_tracer",  "src/syscall_tracer/syscall_tracer.py"),
    ("latency",         "src/latency_histogram/latency.py"),
]


def _load_module_from_path(name, path):
    """Load a module from a file path without executing it as __main__."""
    spec   = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    # Patch out the BCC import so we don't need it installed
    sys.modules.setdefault("bcc", _FakeBCC())
    try:
        spec.loader.exec_module(module)
    except SystemExit:
        pass  # Some loaders call sys.exit on import-time checks
    return module


class _FakeBCC:
    """Minimal stub so `from bcc import BPF` doesn't fail."""
    class BPF:
        XDP = 0
        def __init__(self, **kwargs): pass
        def load_func(self, *a, **kw): return None
        def attach_xdp(self, *a, **kw): pass
        def remove_xdp(self, *a, **kw): pass
        def trace_print(self): pass
        def __getitem__(self, key): return _FakeMap()

    def __getattr__(self, name):
        return lambda *a, **kw: None


class _FakeMap:
    def open_perf_buffer(self, *a, **kw): pass
    def perf_buffer_poll(self): pass
    def print_log2_hist(self, *a): pass
    def clear(self): pass
    def __getitem__(self, key): return type("V", (), {"value": 0})()


class LoaderSmokeTests(unittest.TestCase):

    def test_loader_files_exist(self):
        for name, relpath in LOADER_INFO:
            path = os.path.join(REPO_ROOT, relpath)
            self.assertTrue(os.path.isfile(path), f"Loader missing: {relpath}")

    def test_bpf_src_paths_resolve(self):
        """Each loader's BPF_SRC should point to an existing .bpf.c file."""
        for name, relpath in LOADER_INFO:
            path   = os.path.join(REPO_ROOT, relpath)
            module = _load_module_from_path(name, path)
            bpf_src = getattr(module, "BPF_SRC", None)
            self.assertIsNotNone(bpf_src, f"{name}: BPF_SRC not defined")
            self.assertTrue(
                os.path.isfile(bpf_src),
                f"{name}: BPF_SRC={bpf_src!r} does not exist"
            )

    def test_main_function_defined(self):
        for name, relpath in LOADER_INFO:
            path   = os.path.join(REPO_ROOT, relpath)
            module = _load_module_from_path(name, path)
            self.assertTrue(
                callable(getattr(module, "main", None)),
                f"{name}: no callable 'main' found"
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
