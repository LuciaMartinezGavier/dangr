from pprint import pprint
from copy import deepcopy
from typing import Final
from dangr_c.jasm_rule import JasmRuleEditor

class DangrInter:
    def __init__(self,
        meta: dict,
        config: dict,
        jasm_rule: JasmRuleEditor,
        assigns: list[str],
        deps: list[str],
        constraints: list[str],
        satisfiable: bool,
        msg: str,
        ):
        self.meta = meta
        self.config = config
        self.jasm_rule = jasm_rule
        self.assigns = assigns
        self.deps = deps
        self.constraints = constraints
        self.satisfiable = satisfiable
        self.msg = msg
        jasm_rule.add_anchore('_target', pattern_idx=-1)
        self.address_captures = jasm_rule.address_captures()
        assigned_variables =  [assign.split(' = ', 1)[0] for assign in self.assigns]
        self.variables = jasm_rule.variables() + assigned_variables
        self.simulation_target = '_target'

    def to_dict(self) -> dict:
        dangr_dict = deepcopy(self.__dict__)
        dangr_dict['jasm_rule'] = self.jasm_rule.get_rule()
        return dangr_dict

    def pprint_title(self, title, width) -> None:
        nbr_dashes = int((width - (len(title)+2))/2)
        print('-'*nbr_dashes, title, '-'*nbr_dashes)

    def pprint(self) -> None:
        line_width: Final = 80

        self.pprint_title('Meta', line_width)
        pprint(self.meta)
        self.pprint_title('Config', line_width)
        pprint(self.config)
        self.pprint_title('Given', line_width)
        pprint(self.jasm_rule.get_rule())
        self.pprint_title('Assigns', line_width)
        pprint(self.assigns)
        self.pprint_title('Dependencies', line_width)
        pprint(self.deps)
        self.pprint_title('Constraints', line_width)
        pprint(self.constraints)
        self.pprint_title('Report', line_width)
        print(self.msg)
        print('expect satisfiable:', self.satisfiable)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, DangrInter) and self.meta == other.meta and\
            self.config == other.config and self.msg == other.msg and\
            self.jasm_rule.get_rule() == other.jasm_rule.get_rule()\
            and self.assigns == other.assigns and self.deps == other.deps and\
            self.constraints == other.constraints and self.satisfiable and other.satisfiable
