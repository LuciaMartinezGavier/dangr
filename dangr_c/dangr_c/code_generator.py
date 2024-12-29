from typing import cast
import yapf # type: ignore
from jinja2 import Environment, FileSystemLoader
from dangr_c.jasm_rule import JasmRuleEditor, JasmRule

class DangrGenerator:
    def __init__(
        self,
        intermediate_repr: dict # type: ignore [type-arg]
    ) -> None:
        self.intermediate_repr = intermediate_repr
        self.intermediate_repr['_target'] = '_target'

        jasm_rule = cast(JasmRule, intermediate_repr['jasm_rule'])
        editor = JasmRuleEditor(jasm_rule)

        editor.add_anchore('_target', pattern_idx=-1)
        self.intermediate_repr['address_captures'] = editor.address_captures()
        self.intermediate_repr['var_captures'] = editor.variables()
        self.intermediate_repr['jasm_rule'] = editor.get_rule()

    def generate_code(self) -> str:
        """
        Generates the complete Python code based on the provided parsed code and template.

        :param parsed_rules: Parsed code structure containing imports, functions, etc.
        :return: The generated Python code as a string.
        """
        env = Environment(loader=FileSystemLoader(''), autoescape=True)
        template = env.get_template('dangr_template.j2')
        rendered = template.render(self.intermediate_repr)

        formatted, _ = yapf.yapf_api.FormatCode(rendered)
        return str(formatted)
