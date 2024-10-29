# Dangr compiler

## Getting started

```bash
# install
poetry shell
poetry install

# test
pytest

# Run
python dangr_c.py <rule_name>.yml
```

The program will generate a `<rule_name>.py` file that has the code necessary
to detect the pattern specified in `<rule_name>.yaml` (in the same directory as the given file).

You can find some rule examples in `test_files/*.yaml`.

The generated file can be imported as a library with

```python
from <rule_name> import detect

binary_path = "path/to/the/rule.yaml"
max_depth = 2

detection_result = detect(binary_path, max_depth)
if detection_result.detected:
    print(detection_result.message)
else:
    print("Not found")
```

Or can be used with the CLI:

```bash
python <rule_name>.py --max-depth <n> --binary-path <path/to/the/rule.yaml>
```

The max depth argument is the maximum number of steps to execute backwards when solving arguments. It is ignored when `solve_arguments` is `False` and for both the library or CLI, max-depth is optional.

<!-- - `call_depth` (`int`): the call depth considered when constructing the dependency graph -->

## Dangr language

The language is declarative and very structured. It has 7 stages (some are optional).


## 1. Meta

Here it goes any dictionary with metadata such as authors, licence, ...
It will be included in the generated code as a dictionary and is not validated so any info could go here.
It is not used anywere else.

## 2. Config

All the arguments that influence the generated code have to be specified here. They are all optional.
The posible arguments are:

- `solve_arguments` (`bool`): By default is `False`. If `True` the arguments of the function will be concretized before the analysis. Note that the analysis is more complete but the performance might decreace.
- `little_endian` (`bool`): By default it follows the architecture. If `true` the memory contents will be reversed.

## 3. given
This section defines the **structural pattern**, it is the first filter and fastest part of the analysis.

See [JASM](https://github.com/JukMR/JASM) for the syntax.


## 4. where

List of `<where-expr>`.
A where expression can be an assignment such as `foo = *ptr` or `foo = bar` or `foo = arg(1, call_addr, 4)`. Namely,
any variable can be assigned (and declared) as:
- the dereference of other variable
- other variable
- the argument of some function call
    - `arg(<argument_index>, <call_address_capture>, <argument_byte_size>)`
    - The argument supports arguments with index form 1 to 6.

Also, a where expression can be a logic expression of dependencies.

A dependency is written as `(foo -> bar)`. This means that the generated code will check if
variable `foo` affects the value of `bar`, in other words, `bar` depends on `foo`.

The following are valid dependency expressions:
```yaml
- (a -> b) and (b -> c) and (not (a-> c))
- (g -> b)
- (_anyarg -> a)
```

`_anyarg` referes to any argument of the current function being analyzed,
i.e. the function where the structural pattern matched.

All findings that don't satisfy the dependency expressions will be filtered

```
<where-expr>: <assgn> | <dep-expr>

<assgn>: <lvalue> = <rvalue>
<lvalue>: <variable>
<rvalue>: <deref> | <arg> | <variable>
<deref>: *<variable>
<arg>: arg(<idx>, <addr_capture>, <size>)

<dep>: (<source> -> <target>)
<source>: <variable> | '_anyarg'
<target>: <variable> | '_anyarg'

<dep-expr>: (<dep>)
          | <dep-expr> or <dep-expr>
          | <dep-expr> and <dep-expr>
          | not <dep-expr>
```

## 5. shuch-that
List of `<such-that-expr>`. A such-that expression can be any logical expression that uses literals or variables
declared in the where or given sections.

Each expression here will set a constraint goal in the analysis.

Each constraint is bounded to an execution state, which corresponds to a certain code address.
The state (or states) for each constraint is the state where the last variable is defined.

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

## 6. then
The then section is just a boolean that indicates if the analysis is supposed to find a
satisfiable state or not.

```
<then-expr>: True | False
```
By default it's True.

## 7. report
Here a message is set, so if the pattern is found in the binary this message is returned. 

```
<report-expr>: "<str>"
```
