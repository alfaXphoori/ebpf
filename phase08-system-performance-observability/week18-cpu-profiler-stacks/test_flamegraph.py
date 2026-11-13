#!/usr/bin/env python3
"""Unit tests for Week 18 flamegraph.py renderer (no root required)."""

import unittest

import flamegraph


class TestFlamegraphRenderer(unittest.TestCase):
    def test_parse_folded_and_render_svg(self):
        lines = [
            "busy;spin_[k] 10",
            "busy;hot_path 20",
            "bad line without count",
            "",
        ]
        root = flamegraph.parse_folded(lines)
        self.assertEqual(root.count, 30)
        self.assertEqual(flamegraph.depth_of(root), 3)

        svg = flamegraph.render(root, width=800, title="Test Flame Graph")
        self.assertTrue(svg.startswith("<svg "))
        self.assertTrue(svg.endswith("</svg>"))
        self.assertIn("Test Flame Graph", svg)
        self.assertIn("30 samples", svg)
        self.assertIn("hot_path (20 samples, 66.67%)", svg)
        self.assertIn("spin_[k] (10 samples, 33.33%)", svg)

    def test_kernel_vs_user_colors(self):
        self.assertNotEqual(flamegraph.color("tcp_sendmsg_[k]"), flamegraph.color("main"))

    def test_empty_input_does_not_divide_by_zero(self):
        root = flamegraph.parse_folded([])
        svg = flamegraph.render(root, width=600, title="Empty")
        self.assertIn("0 samples", svg)


if __name__ == "__main__":
    unittest.main()
