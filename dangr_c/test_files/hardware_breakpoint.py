"""
# Automatically generated code for binary analysis using 'dangr'.
#
# This script defines a function, `detect`
# The function uses pattern-matching rules (JASM)
# to detect specific structural findings in the binary, which are then analyzed
# through symbolic execution and constraint solving.
"""

from typing import Final
from collections import namedtuple
import sys
import argparse
from dangr_rt.dangr_analysis import DangrAnalysis
from dangr_rt.jasm_findings import structural_filter
from dangr_rt.expression import *
from dangr_rt.dangr_types import Argument
from dangr_rt.dangr_argparse import DangrArgparse

JASM_PATTERN: Final[dict] = {
    'pattern': [{
        'call': ['@any', '<ptrace@plt>'],
        'address-capture': 'ptrace_call'
    }]
}
META: Final[dict] = {}

DetectionResult = namedtuple("DetectionResult", ["detected", "message"])


def detect(binary_path: str, config: dict) -> bool:
    s_findings = structural_filter(binary_path, JASM_PATTERN)
    dangr = DangrAnalysis(binary_path, config)
    vf = dangr.get_variable_factory()

    for s_finding in s_findings:
        dangr.set_finding(s_finding)
        ptrace_call = s_finding.address_captures["ptrace_call"]
        _target = s_finding.address_captures["_target"]
        a1 = vf.create_from_argument(Argument(1, ptrace_call, 4))
        a3 = vf.create_from_argument(Argument(3, ptrace_call, 4))

        dangr.add_variables([a1, a3])
        dangr.add_constraint(Eq(a1, 3))
        dangr.add_constraint(Eq(a3, 848))
        concrete_values = dangr.concretize_fn_args()
        found_states = dangr.simulate(_target, concrete_values)
        if not found_states:
            break
        if not dangr.satisfiable(found_states):
            return DetectionResult(
                True,
                "Debugging evasion through hardware breakpoint detection")

    return DetectionResult(False, None)


if __name__ == "__main__":

    parser = DangrArgparse(
        "Run binary analysis and detect a beheavorial pattern")
    parser.add_argument("binary_path",
                        type=str,
                        help="Path to binary to analyze.")
    args = parser.parse_args()
    result = detect(args.binary_path, args.config)

    if result.detected:
        print(result.message)
        sys.exit(1)

    sys.exit(0)
