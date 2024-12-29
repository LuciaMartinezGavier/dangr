from dataclasses import dataclass

JasmRule = dict[str, 'JasmRule'] | list['JasmRule'] | str

class JasmRuleEditor:
    def __init__(self, rule: JasmRule):
        self.rule = rule

    def get_rule(self) -> JasmRule:
        """
        Return the rule.
        Jasm should be able to process this dict afterwards
        """
        return self.rule

    def add_anchore(self, anchor_name: str, pattern_idx: int) -> None:
        """
        Adds an anchore capture in the rule, in the pattern idx.
        The indexes are python-like, for example, -1 is valid.
        """
        # instruction = self.rule['pattern'][pattern_idx]
        # key = [k for k in instruction.keys()][0]
        # instruction[key]['address_capture'] = anchor_name

    def add_var_anchores(self) -> None:
        """
        Adds an address capture for each variable in the pattern.
        (This one is a nice to have, i can implement this with `add_anchore()`)
        """

    def variables(self) -> list[str]:
        """
        Returns a list with all the variable names in the pattern
        A variable captures a register or literal for example `$any-var`
        """
        # MOCKED
        match self.rule['pattern']:
            case 'mock hardware_breakpoint':
                return []
            case 'software_breakpoint_pattern':
                return ['y', 'z', 'opcode_addr']
            case 'mock small_bmp_support_lib_12c5':
                return []
            case 'mock uncontrolled_input_0078':
                return ['ptr']


    def address_captures(self) -> list[str]:
        """
        Returns a list with all the address captures names in the pattern
        """
        # MOCKED
        match self.rule['pattern']:
            case 'mock hardware_breakpoint':
                return ['ptrace_call', '_target']
            case 'software_breakpoint_pattern':
                return ['_target']
            case 'mock small_bmp_support_lib_12c5':
                return ['alloc_call', '_target']
            case 'mock uncontrolled_input_0078':
                return ['_target']
