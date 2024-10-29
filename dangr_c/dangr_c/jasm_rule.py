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
        return []

    def address_captures(self) -> list[str]:
        """
        Returns a list with all the address captures names in the pattern
        """
        return ['ptrace_call', '_target']

@dataclass
class VariableMatch:
    name: str
    value: str
    addr: int

@dataclass
class AddressMatch:
    name: str
    value: int

# jasm returns a set of JasmMatch's
class JasmMatch:

    def variables(self) -> list[VariableMatch]:
        """
        Returns a dict with all the variables matched
        Including
        - The variable name
        - The register/literal matched
        - The address capture in the instruction if it exists
        """
        return []

    def address_captures(self) -> list[AddressMatch]:
        """
        Returns a list with all the address captures.
        The keys are the anchore's names and the value is the match
        """
        return []
