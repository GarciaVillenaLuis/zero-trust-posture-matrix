#!/usr/bin/env python3
"""
Unit tests for Zero Trust Architecture Maturity Evaluator.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from zero_trust_eval import ZeroTrustEvaluator, format_zt_table, get_default_sample_matrix


class TestZeroTrustEvaluator(unittest.TestCase):
    def setUp(self):
        self.evaluator = ZeroTrustEvaluator()

    def test_classify_stages(self):
        self.assertEqual(self.evaluator.classify_stage(30), "TRADITIONAL")
        self.assertEqual(self.evaluator.classify_stage(60), "INITIAL")
        self.assertEqual(self.evaluator.classify_stage(80), "ADVANCED")
        self.assertEqual(self.evaluator.classify_stage(95), "OPTIMAL")

    def test_evaluate_default_matrix(self):
        data = get_default_sample_matrix()
        report = self.evaluator.evaluate_payload(data)
        self.assertEqual(report.composite_index, 95)
        self.assertEqual(report.overall_stage, "OPTIMAL")
        self.assertEqual(len(report.pillars), 5)
        self.assertIn("identity", report.pillars)
        self.assertEqual(report.pillars["identity"].score, 96)

    def test_table_formatting(self):
        data = get_default_sample_matrix()
        report = self.evaluator.evaluate_payload(data)
        table_output = format_zt_table(report)
        self.assertIn("NIST SP 800-207", table_output)
        self.assertIn("Identity", table_output)
        self.assertIn("OPTIMAL", table_output)


if __name__ == "__main__":
    unittest.main()
