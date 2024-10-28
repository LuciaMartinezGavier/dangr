from dangr_c.expr_parser import WhereExprParser, SuchThatExprParser
from pyparsing.exceptions import ParseException
import yaml
from cerberus import Validator
from dangr_c.dangr_code import DangrInter
from dangr_c.jasm_rule import JasmRuleEditor
from dangr_c.visitor import WhereExprVisitor, SuchThatExprVisitor, ExprType

class DangrParser:
    DANGR_SCHEMA = {
        'meta': {
            'type': 'dict',
            'default': {}
        },
        'config': {
            'type': 'dict',
            'schema': {
                'solve_arguments': {'type': 'boolean', 'default': False},
                'little_endian': {'type': 'boolean', 'required': False},
            },
            'default': {}
        },
        'given': {'type': 'dict'},
        'where': {'type': 'list', 'schema': {'type': 'string'}},
        'such-that': {'type': 'list', 'schema': {'type': 'string'}},
        'then': {'type': 'boolean', 'default': True},
        'report': {'type': 'string', 'default': 'Pattern Matched'},
    }

    def __init__(self, rule_path) -> None:
        self.rule_path = rule_path
        self.ast: dict = {}

        self.assigns: list[str] = []
        self.constraints: list[str] = []
        self.deps: list[str] = []

    def load_yaml(self):
        with open(self.rule_path, 'r', encoding='utf-8') as file:
            data = yaml.safe_load(file)
        return data

    def check_consistency(self):
        # TODO
        pass

    def parsing_error(self, msg):
        raise ValueError(f"Parsing error: {msg}")

    def parse_expressions(self, exp_parser, visitor, expressions) -> None:
        for exp in expressions:
            try:
                parsed_exp = exp_parser.parse(exp)
            except ParseException as exc:
                raise ValueError(
                    f'Invalid expression "{exp}": {exc.msg} found {exc.found} (col: {exc.col})'
                ) from exc

            visitor.visit(parsed_exp)
            match visitor.expr_type:
                case ExprType.ASSIGN:
                    self.assigns.append(visitor.formula)
                case ExprType.DEP_EXPR:
                    self.deps.append(visitor.formula)
                case ExprType.CONSTR:
                    self.constraints.append(visitor.formula)

    def parse_where(self):
        expressions = self.ast['where']
        exp_parser = WhereExprParser()
        visitor = WhereExprVisitor(reverse=self.ast['config'].get('little_endian', None))
        self.parse_expressions(exp_parser, visitor, expressions)

    def parse_such_that(self):
        expressions = self.ast['such-that']
        exp_parser = SuchThatExprParser()
        visitor = SuchThatExprVisitor()
        self.parse_expressions(exp_parser, visitor, expressions)

    def parse_dangr(self) -> DangrInter:
        v = Validator(self.DANGR_SCHEMA)
        if not v.validate(self.load_yaml()):
            self.parsing_error(f'Invalid dangr {v.errors}')
        self.ast = v.document

        self.parse_where()
        self.parse_such_that()

        return DangrInter(
            meta=self.ast['meta'],
            config=self.ast['config'],
            jasm_rule=JasmRuleEditor(self.ast['given']),
            assigns=self.assigns,
            deps=self.deps,
            constraints=self.constraints,
            satisfiable=self.ast['then'],
            msg=self.ast['report']
        )
