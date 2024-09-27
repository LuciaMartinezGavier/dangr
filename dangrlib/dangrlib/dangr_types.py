import angr
import claripy

Address = int
Path = str
CFGNode = angr.analyses.cfg.CFGNode
AngrExpr = claripy.ast.bv.BV | claripy.ast.bool.Bool
BYTE_SIZE = 8
ALLIGNMENT_OFFSET = 4