# Dangr compiler
<!-- 

```bash
python dangr_gen.py <rule_name>.yml
```
- importa Dangr
- genera `<rule_name>.py` importable y cli-able
- captura excepciones e imprime en stderr

```
python <rule_name>.py --max-depth=<n> bin
```
- max-depth es opcional
- pasa los argumentos directo al dangr-rt `{'max-depth':n}`
- retorna 0 o 1 y el mensaje

## dangr

Dangr.generate(rule_path, output_path) -> None
raises Exception on error

----
sub-template para cada generador (structural, symbolic...)


# dangr-rt
```
Dangr.set_config(config:dict[str, Any])
``` -->


# Dangr

## meta

- `authors` (`list[str]`): easy to imagine what this means


## config

- `solve_arguments` (`bool`): if true the arguments of the function will be concretized before the analysis
- `backward_max_depth` (`int`): maximum number of steps to execute backwards when solving arguments. Optional. Ignored when `solve_arguments` is false
- `little_endian` (`bool`): if true the memory contents will be reversed
- `call_depth` (`int`): the call depth considered when constructing the dependency graph


## given

jasm pattern with jasm syntax

defines `<variable>` and `<addr_capture>`


## where
list of `<where-expr>`

```
<where-expr>: <assgn> | <dep-expr>

<assgn>: <lvalue> = <rvalue>
<lvalue>: <variable>
<rvalue>: <deref> | <arg>
<deref>: *<variable>
<arg>: arg(<addr_capture>, <number>)

<dep-expr>: (<dep>)
          | <dep-expr> or <dep-expr>
          | <dep-expr> and <dep-expr>
          | not <dep-expr>
```

The assignments also declare variables.
No constraint is set here

All findings that not satisfy the dependency expressions will be filtered


## shuch-that
a list of `<such-that-expr>`

```
<such-that-expr>: <arith-expr> = <arith-expr>
                | <such-that-expr> and <such-that-expr>
                | <such-that-expr> or <such-that-expr>
                | not <such-that-expr>
                | upper_unbounded(<arith-expr>)

<arith-expr>: <variable> | <constant>
            | <arith-expr> + <arith-expr>
            | <arith-expr> * <arith-expr>
            | <arith-expr> - <arith-expr>
            | <arith-expr> / <arith-expr>

```

## then

```
<then-expr>: satisfiable | unsatisfiable
```
by default is satisfiable

## report
```
<report-expr>: "<str>"
```
