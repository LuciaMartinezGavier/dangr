from abc import abstractmethod
from typing import override
from pyparsing import (
    oneOf, Word, Suppress, Keyword, ParserElement, Group, Combine,
    alphas, alphanums, nums, opAssoc, Literal, ParseResults, infixNotation
)

NodeName = str
Atom = str
Parent = dict[NodeName, 'Node']
Node = Atom | Parent

class ExprParser:
    """
    Expression parser
    Defines some common logic for parsers
    """
    HEX_PREFIX = oneOf("0x 0X")
    HEX_DIGITS = Word('0123456789ABCDEFabcdef')

    LBRACKET = Suppress(Literal('('))
    RBRACKET = Suppress(Literal(')'))
    COMMA = Suppress(Literal(','))
    DEREF = Suppress('*')

    AND = Keyword('and')
    OR = Keyword('or')
    NOT = Keyword('not')

    @property
    def constant(self) -> ParserElement:
        hex_number = Combine(self.HEX_PREFIX + self.HEX_DIGITS)
        return Group(hex_number | Word(nums))

    @property
    def identifier(self) -> ParserElement:
        return Group(Word(alphas, alphanums + '_'))

    @property
    @abstractmethod
    def expr(self) -> ParserElement:
        pass

    def _to_dict(self, res: dict | ParseResults) -> dict | list:
        if isinstance(res, dict):
            return res

        name = res.get_name()
        if name:
            return {res.get_name(): res.as_dict()}
        return res.as_list()

    def _infix_dict(self, tokens: ParseResults) -> dict:
        parse_result = tokens[0]
        if len(parse_result) == 2:
            return { parse_result[0]: {
                    'exp': self._to_dict(parse_result[1]),
            }}

        return { parse_result[1]: {
            'lft': self._to_dict(parse_result[0]),
            'rgt': self._to_dict(parse_result[2]),
        }}

    def _logic(self, atom: ParserElement) -> ParserElement:
        logic_expr = infixNotation(
            atom,
            [
                (self.NOT, 1, opAssoc.RIGHT, self._infix_dict),
                (self.AND, 2, opAssoc.RIGHT,  self._infix_dict),
                (self.OR,  2, opAssoc.RIGHT,  self._infix_dict),
            ]
        )
        return logic_expr

    def _remove_unnecesary_lists(self, data: dict | list | str) -> Node:
        match data:
            case dict() as d:
                return self._remove_unnecesary_lists_in_dict(d)
            case list() as l if len(l) == 1:
                return self._remove_unnecesary_lists(l[0])
            case str() as s:
                return s
            case _:
                raise ValueError(f"Malformed AST {data}")

    def _remove_unnecesary_lists_in_dict(self, data: dict) -> Node:
        return {k: self._remove_unnecesary_lists(v) for k, v in data.items()}

    def parse(self, raw_string: str) -> Node:
        ast = self.expr.parse_string(raw_string, parseAll=True).as_dict()
        return self._remove_unnecesary_lists(ast)

class WhereExprParser(ExprParser):
    ARG = Suppress('arg')
    ARROW = Suppress('->')
    ASSIGN_EQ = Suppress('=')
    ANYARG = Keyword('_anyarg')

    @property
    def deref(self) -> ParserElement:
        return Group(
            self.DEREF
            + self.identifier('var')
        )('deref')

    @property
    def arg(self) -> ParserElement:
        return Group(
            self.ARG
            + self.LBRACKET
            + self.constant('idx')
            + self.COMMA
            + self.identifier('call')
            + self.COMMA
            + self.constant('size')
            + self.RBRACKET
        )('arg')

    @property
    def assign(self) -> ParserElement:
        """
        <assign>: <lv> = <rv>
        <rv>: <deref> | <arg> | <identifier>
        """
        return Group(
            self.identifier('lv')\
            + self.ASSIGN_EQ\
            + Group(self.deref | self.arg | self.identifier)('rv')
        )('asgn')

    @property
    def dep(self) -> ParserElement:
        """
        <dep>: (<source> -> <target>)
        <source>: <identifier> | '_anyarg'
        <target>: <identifier> | '_anyarg'
        """
        return Group(
            self.LBRACKET
            + (self.identifier | self.ANYARG)('src')
            + self.ARROW
            + (self.identifier | self.ANYARG)('trg')
            + self.RBRACKET
        )('dep')

    @property
    def dep_expr(self) -> ParserElement:
        """
        <dep_expr>: <dep_expr> or <dep_expr>
                  | <dep_expr> and <dep_expr>
                  | not <dep_expr>
                  | <dep>
        """
        return self._logic(self.dep)

    @override
    @property
    def expr(self) -> ParserElement:
        """
        <where>: <assign> | <dep_expr>
        """
        return Group(self.assign | self.dep_expr)('where')



class SuchThatExprParser(ExprParser):
    ADD = Literal('+')
    MUL = Literal('*')
    SUB = Literal('-')
    DIV = Literal('/')

    ADD.setParseAction(lambda tokens: 'add')
    MUL.setParseAction(lambda tokens: 'mul')
    SUB.setParseAction(lambda tokens: 'sub')
    DIV.setParseAction(lambda tokens: 'div')

    TRUE = Keyword('True')
    FALSE = Keyword('False')

    UPPER_UNBOUNDED_PTR = Suppress('upper_unbounded_ptr')
    CONSTRAINT_EQ = Literal('=')

    @property
    def arith(self) -> ParserElement:
        arith_expr = infixNotation(
            self.constant | self.identifier,
            [
                (self.MUL, 2, opAssoc.RIGHT, self._infix_dict),
                (self.DIV, 2, opAssoc.RIGHT, self._infix_dict),
                (self.ADD, 2, opAssoc.RIGHT, self._infix_dict),
                (self.SUB, 2, opAssoc.RIGHT, self._infix_dict),
            ]
        )
        return arith_expr

    @property
    def upper_unbounded_ptr(self) -> ParserElement:
        """
        <upper_unbounded_ptr>: upper_unbounded_ptr(<bounded_exp>, <is_ptr>)
        <bounded_exp>: <arith>
        <is_ptr>: True | False
        """
        return Group(
            self.UPPER_UNBOUNDED_PTR
            + self.LBRACKET
            + self.arith('bounded_exp')
            + self.RBRACKET
        )("upper_unbounded_ptr")

    @property
    def constr_eq(self) -> ParserElement:
        return Group(
            self.arith('lft')
            + self.CONSTRAINT_EQ
            + self.arith('rgt')
        )('eq')

    @override
    @property
    def expr(self) -> ParserElement:
        return Group(self._logic(self.constr_eq) | self.upper_unbounded_ptr)("such_that")
