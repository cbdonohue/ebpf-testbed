#!/usr/bin/env python3
"""
test_syntax.py — Verify .bpf.c files have no obvious syntax issues.

Checks that each eBPF C source file:
  - Exists and is non-empty
  - Contains required includes
  - Contains the expected program entry function
  - Has balanced braces

Does NOT require a kernel or BCC installed — purely static checks.
"""

import os
import sys
import glob
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR   = os.path.join(REPO_ROOT, "src")

# Maps filename -> (required_include_fragment, expected_function_fragment)
EXPECTED = {
    "hello.bpf.c":            ("<uapi/linux/ptrace.h>", "kprobe__sys_clone"),
    "packet_counter.bpf.c":   ("<linux/if_ether.h>",    "xdp_packet_counter"),
    "syscall_tracer.bpf.c":   ("BPF_PERF_OUTPUT",       "sys_enter_execve"),
    "latency.bpf.c":          ("BPF_HISTOGRAM",          "blk_account_io_start"),
}


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
        for fname, (include_frag, fn_frag) in EXPECTED.items():
            path = self._find_file(fname)
            src  = self._read(path)
            self.assertIn(
                include_frag, src,
                f"{fname}: missing expected fragment '{include_frag}'"
            )
            self.assertIn(
                fn_frag, src,
                f"{fname}: missing expected function/symbol '{fn_frag}'"
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
