#!/usr/bin/env python3
"""
test_loaders.py — Smoke-test that Python loader scripts import cleanly.

Validates:
  - Each loader module can be imported without errors
  - Required top-level names (main, BPF_SRC) are present
  - BPF_SRC paths resolve to existing .bpf.c files
  - Loaders do NOT import bcc (CO-RE architecture uses ctypes + bpftool)

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
    try:
        spec.loader.exec_module(module)
    except SystemExit:
        pass  # Some loaders call sys.exit on import-time checks
    return module


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

    def test_no_bcc_import_in_loaders(self):
        """CO-RE loaders must not import BCC; they use ctypes + bpftool."""
        for name, relpath in LOADER_INFO:
            path = os.path.join(REPO_ROOT, relpath)
            with open(path) as f:
                src = f.read()
            self.assertNotIn(
                "from bcc import", src,
                f"{name}: loader still imports BCC — should use ctypes/libbpf"
            )
            self.assertNotIn(
                "import bcc", src,
                f"{name}: loader still imports BCC — should use ctypes/libbpf"
            )

    def test_loaders_use_ctypes(self):
        """CO-RE loaders should use ctypes for struct definitions."""
        for name, relpath in LOADER_INFO:
            path = os.path.join(REPO_ROOT, relpath)
            with open(path) as f:
                src = f.read()
            self.assertIn(
                "ctypes", src,
                f"{name}: loader does not use ctypes (expected for CO-RE)"
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
