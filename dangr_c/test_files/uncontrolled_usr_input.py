"""
# Automatically generated code for binary analysis using 'dangr_c'.
#
# the Rule class extends the DangrAnalysis, which defines a method
# analize(jasm_pattern) which uses asm pattern-matching
# to detect specific structural findings in the binary,
# and then they are analyzed through symbolic execution and 
# constraint solving.
"""

import sys
from typing import Final, override
from dangr_rt import *

JASM_PATTERN: Final[dict] = {'pattern': 'mock uncontrolled_input_0078'}
META: Final[dict] = {}


class Rule(DangrAnalysis):

    @override
    def _analyze_asm_match(self, jasm_match: JasmMatch) -> str | None:
        msg = "Pointer from user input is not bounded"
        _target = jasm_match.addrmatch_from_name("_target").value
        ptr = self._create_var_from_capture(
            jasm_match.varmatch_from_name("ptr"))
        if not any(self._depends(_arg, ptr) for _arg in self._get_fn_args()):
            return
        self._add_constraint(IsMax(ptr))
        found_states = self._simulate(_target)
        if self._satisfiable(found_states):
            return msg


if __name__ == "__main__":
    parser = DangrArgparse(
        "Run binary analysis and detect a beheavorial pattern")
    parser.add_argument("-b",
                        "--binary-path",
                        type=str,
                        required=True,
                        help="Path to binary to analyze.")

    args = parser.dangr_parse_args()
    rule = Rule(args.binary_path, args.config)
    report = rule.analyze(JASM_PATTERN)

    if report:
        print(report)
        sys.exit(1)

    sys.exit(0)
