from pyparsing import *
from abc import ABC, abstractmethod
from typing import override

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
    def constant(self):
        hex_number = Combine(self.HEX_PREFIX + self.HEX_DIGITS)
        return Group(hex_number | Word(nums))

    @property
    def identifier(self):
        return Group(Word(alphas, alphanums + '_'))

    @property
    @abstractmethod
    def expr(self):
        pass

    def _to_dict(self, res: dict | ParseResults) -> dict | list:
        if isinstance(res, dict):
            return res

        name = res.get_name()
        if name:
            return {res.get_name(): res.as_dict()}
        else:
            return res.as_list()

    def _infix_dict(self, tokens):
        parse_result = tokens[0]
        if len(parse_result) == 2:
            return { parse_result[0]: {
                    'exp': self._to_dict(parse_result[1]),
            }}
        else:
            return { parse_result[1]: {
                'lft': self._to_dict(parse_result[0]),
                'rgt': self._to_dict(parse_result[2]),
            }
        }

    def _logic(self, atom):
        logic_expr = infixNotation(
            atom,
            [
                (self.NOT, 1, opAssoc.RIGHT, self._infix_dict),
                (self.AND, 2, opAssoc.RIGHT,  self._infix_dict),
                (self.OR,  2, opAssoc.RIGHT,  self._infix_dict),
            ]
        )
        return logic_expr

    def _remove_unnecesary_lists(self, data):
        if isinstance(data, dict):
            return {k: self._remove_unnecesary_lists(v) for k, v in data.items()}
        elif isinstance(data, list):
            if len(data) == 1:
                return self._remove_unnecesary_lists(data[0])
            else:
                return [self._remove_unnecesary_lists(item) for item in data]
        else:
            return data


    def parse(self, raw_string):
        ast = self.expr.parse_string(raw_string, parseAll=True).as_dict()
        return self._remove_unnecesary_lists(ast)

class WhereExprParser(ExprParser):
    ARG = Suppress('arg')
    ARROW = Suppress('->')
    ASSIGN_EQ = Suppress('=')
    ANYARG = Keyword('_anyarg')

    @property
    def deref(self):
        return Group(
            self.DEREF
            + self.identifier('var')
        )('deref')

    @property
    def arg(self):
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
    def assign(self):
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
    def dep(self):
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
    def dep_expr(self):
        """
        <dep_expr>: <dep_expr> or <dep_expr>
                  | <dep_expr> and <dep_expr>
                  | not <dep_expr>
                  | <dep>
        """
        return self._logic(self.dep)

    @override
    @property
    def expr(self):
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
    def arith(self):
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
    def upper_unbounded_ptr(self):
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
    def constr_eq(self):
        return Group(
            self.arith('lft')
            + self.CONSTRAINT_EQ
            + self.arith('rgt')
        )('eq')

    @override
    @property
    def expr(self):
        return Group(self._logic(self.constr_eq) | self.upper_unbounded_ptr)("such_that")
