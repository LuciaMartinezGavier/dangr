from typing import Any, cast
from cerberus import Validator # type: ignore
from pyparsing.exceptions import ParseException
import yaml

from dangr_c.expr_parser import WhereExprParser, SuchThatExprParser, ExprParser
from dangr_c.code_generator import DangrGenerator
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

    def __init__(self, rule_path: str) -> None:
        self.rule_path = rule_path
        self.ast: dict[str, Any] = {}

        self.assigns: list[str] = []
        self.variables: list[str] = []
        self.constraints: list[str] = []
        self.deps: list[str] = []

    def load_yaml(self) -> dict:
        with open(self.rule_path, 'r', encoding='utf-8') as file:
            data = cast(dict, yaml.safe_load(file))
        return data

    def parsing_error(self, msg: str) -> None:
        raise ValueError(f"Parsing error: {msg}")

    def parse_expressions(self,
        exp_parser: ExprParser, visitor: WhereExprVisitor | SuchThatExprVisitor,
        expressions: list[str]
    ) -> None:
        for exp in expressions:
            try:
                parsed_exp = exp_parser.parse(exp)
            except ParseException as exc:
                raise ValueError(
                    f'Invalid expression "{exp}": {exc.msg} (col: {exc.col})'
                ) from exc

            visitor.visit(parsed_exp)

            if visitor.expr_type is None:
                raise ValueError(f"Expression {exp} doesn't have an ExprType")

            self._store_expression(visitor)

    def _store_expression(self, visitor) -> None:
        match visitor.expr_type:
            case ExprType.ASSIGN:
                self.assigns.append(visitor.formula)
                self.variables.append(visitor.dst_variable)
            case ExprType.DEP_EXPR:
                self.deps.append(visitor.formula)
            case ExprType.CONSTR:
                self.constraints.append(visitor.formula)

    def parse_where(self) -> None:
        expressions = self.ast['where']
        exp_parser = WhereExprParser()
        visitor = WhereExprVisitor(reverse=self.ast['config'].get('little_endian', None))
        self.parse_expressions(exp_parser, visitor, expressions)

    def parse_such_that(self) -> None:
        expressions = self.ast['such-that']
        exp_parser = SuchThatExprParser()
        visitor = SuchThatExprVisitor()
        self.parse_expressions(exp_parser, visitor, expressions)

    def parse_dangr(self) -> DangrGenerator:
        v = Validator(self.DANGR_SCHEMA)
        if not v.validate(self.load_yaml()):
            self.parsing_error(f'Invalid dangr {v.errors}')
        self.ast = v.document

        self.parse_where()
        self.parse_such_that()

        return DangrGenerator(intermediate_repr={
            'meta': self.ast['meta'],
            'config': self.ast['config'],
            'jasm_rule': self.ast['given'],
            'assigns': self.assigns,
            'variables': self.variables,
            'deps': self.deps,
            'constraints': self.constraints,
            'satisfiable': self.ast['then'],
            'msg': self.ast['report']
        })
