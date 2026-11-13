#!/usr/bin/env python3
"""Unit tests for Week 26 validate-policies.py safety rules."""

import importlib.util
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = importlib.util.spec_from_file_location(
    "validate_policies", os.path.join(HERE, "validate-policies.py")
)
vp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vp)


class TestValidatePolicies(unittest.TestCase):
    def test_repo_policies_all_pass(self):
        self.assertEqual(vp.main(), 0)

    def test_rejects_unrestricted_sigkill(self):
        if not hasattr(vp, "yaml"):
            self.skipTest("PyYAML not installed")
        bad_yaml = """\
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: w26-bad-sigkill
spec:
  kprobes:
  - call: "security_file_open"
    args:
    - index: 0
      type: "file"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Postfix"
        values:
        - "/etc/passwd"
      matchActions:
      - action: "Sigkill"
"""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tf:
            tf.write(bad_yaml)
            tmp_path = tf.name
        try:
            errs = vp.check_policy(tmp_path)
            self.assertTrue(any("non-lab path" in e for e in errs), errs)
            self.assertTrue(any("not restricted to a lab-files/" in e for e in errs), errs)
        finally:
            os.unlink(tmp_path)


if __name__ == "__main__":
    unittest.main()
