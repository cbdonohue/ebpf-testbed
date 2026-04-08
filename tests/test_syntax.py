#!/usr/bin/env python3
"""
test_syntax.py — Verify .bpf.c files have no obvious syntax issues.

Checks that each eBPF C source file:
  - Exists and is non-empty
  - Contains required includes (libbpf CO-RE style)
  - Contains the expected program entry function
  - Has balanced braces
  - Uses ring buffer (BPF_MAP_TYPE_RINGBUF) where appropriate

Does NOT require a kernel or BCC installed — purely static checks.
"""

import os
import sys
import glob
import unittest
import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR   = os.path.join(REPO_ROOT, "src")

# Maps filename -> (required_fragment, expected_function_fragment)
# Updated for libbpf CO-RE architecture: vmlinux.h + bpf_helpers.h, ring buffers
EXPECTED = {
    "hello.bpf.c":            ("BPF_MAP_TYPE_RINGBUF",  "kprobe__sys_clone"),
    "packet_counter.bpf.c":   ("<bpf/bpf_helpers.h>",   "xdp_packet_counter"),
    "syscall_tracer.bpf.c":   ("BPF_MAP_TYPE_RINGBUF",  "sys_enter_execve"),
    "latency.bpf.c":          ("BPF_MAP_TYPE_RINGBUF",  "blk_account_io_start"),
}

# All CO-RE programs must include vmlinux.h and bpf_helpers.h
CORE_INCLUDES = ["vmlinux.h", "<bpf/bpf_helpers.h>"]


class BpfSyntaxTests(unittest.TestCase):

    def _find_file(self, filename):
        matches = glob.glob(os.path.join(SRC_DIR, "**", filename), recursive=True)
        self.assertTrue(matches, f"Could not find {filename} under {SRC_DIR}")
        return matches[0]

    def _read(self, path):
        with open(path) as f:
            return f.read()

    def _check_braces(self, src, filename):
        opens  = src.count("{")
        closes = src.count("}")
        self.assertEqual(
            opens, closes,
            f"{filename}: unbalanced braces ({opens} open, {closes} close)"
        )

    def test_files_exist_and_nonempty(self):
        for fname in EXPECTED:
            path = self._find_file(fname)
            size = os.path.getsize(path)
            self.assertGreater(size, 0, f"{fname} is empty")

    def test_required_includes_and_symbols(self):
        for fname, (fragment, fn_frag) in EXPECTED.items():
            path = self._find_file(fname)
            src  = self._read(path)
            self.assertIn(
                fragment, src,
                f"{fname}: missing expected fragment '{fragment}'"
            )
            self.assertIn(
                fn_frag, src,
                f"{fname}: missing expected function/symbol '{fn_frag}'"
            )

    def test_core_includes_present(self):
        """All CO-RE programs must include vmlinux.h and bpf_helpers.h."""
        for fname in EXPECTED:
            path = self._find_file(fname)
            src  = self._read(path)
            for inc in CORE_INCLUDES:
                self.assertIn(
                    inc, src,
                    f"{fname}: missing CO-RE include '{inc}'"
                )

    def test_no_bcc_imports(self):
        """No .bpf.c file should use BCC-style macros."""
        bcc_markers = ["BPF_PERF_OUTPUT", "BPF_HISTOGRAM", "from bcc import"]
        for fname in EXPECTED:
            path = self._find_file(fname)
            src  = self._read(path)
            for marker in bcc_markers:
                self.assertNotIn(
                    marker, src,
                    f"{fname}: found BCC marker '{marker}' — should be CO-RE"
                )

    def test_balanced_braces(self):
        for fname in EXPECTED:
            path = self._find_file(fname)
            src  = self._read(path)
            self._check_braces(src, fname)

    def test_no_tabs_in_indentation(self):
        """Style: BPF programs should use spaces, not tabs, for indentation."""
        for fname in EXPECTED:
            path = self._find_file(fname)
            with open(path) as f:
                for i, line in enumerate(f, 1):
                    if line.startswith("\t"):
                        self.fail(f"{fname}:{i}: line starts with a tab")

    @pytest.mark.skipif(
        not os.path.exists('/sys/kernel/btf/vmlinux'),
        reason="bpftool/BTF not available in CI"
    )
    def test_vmlinux_h_exists(self):
        """vmlinux.h must be present in src/common/ for CO-RE compilation."""
        vmlinux = os.path.join(SRC_DIR, "common", "vmlinux.h")
        self.assertTrue(
            os.path.isfile(vmlinux),
            f"src/common/vmlinux.h missing — run: "
            f"bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/common/vmlinux.h"
        )
        self.assertGreater(os.path.getsize(vmlinux), 1000,
                           "vmlinux.h looks truncated")


if __name__ == "__main__":
    unittest.main(verbosity=2)
