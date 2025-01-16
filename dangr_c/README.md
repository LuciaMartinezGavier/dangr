
# Dangr Compiler

The Dangr compiler is responsible for translating declarative rules into Python programs. These programs, when executed, perform symbolic execution using the angr framework to detect specified patterns or vulnerabilities in binaries.


## Usage

## Compiling Rules

To compile a rule written in Dangr's declarative language, use:

```bash
python dangr_c.py <rule_name>.yaml
```

This will generate a file named `<rule_name>.py` in the same directory as the given rule.

## Running the Generated Code

### As a Python Library

You can import the generated code and use it programmatically:

```python
from <rule_name> import Rule

binary_path = 'path/to/binary'
config = {
    'max_depth': 3,
    'timeout': 10 
}

rule = Rule(binary_path, config)
report = rule.analyze()
print(report)
```

### From the Command Line

Alternatively, execute the generated script directly:

```bash
python <rule_name>.py --binary-path <path/to/the/binary> --max-depth 3 --timeout 10
```
Use `python <rule_name>.py --help` to learn more about the config options.


## Dangr Language

The Dangr declarative language is structured into seven stages with YAML syntax, each with a specific purpose. Some stages are optional:

### 1. Meta

A metadata dictionary that can include details like author and license. This data is included in the generated code but not validated or used elsewhere.

```YAML
meta:
  author: Lucía Martinez Gavier
  type: debugging evation
  cve: cve-2024-3094
```

### 2. Config

Optional configuration for the generated code:

- **`solve_arguments`** (`bool`): If `True`, arguments are concretized before analysis. Improves accuracy but may reduce performance. Default is `False`.
- **`little_endian`** (`bool`): Specifies memory endianness. Defaults to architecture settings.

```YAML
config:
    solve_arguments: true
```

### 3. Given

Defines the **structural pattern**, acting as the first filter for analysis. The syntax follows [JASM](https://github.com/JukMR/JASM).

**Disclaimer!** We are still working on the integration with JASM. We need some extra features, and then we will be able to integrate it. Right now, the JASM output is mocked.

### 4. Where

Defines **dependency and assignment expressions** to refine the findings:

- **Assignment Syntax:**
```yaml
where:
  - foo = *ptr
  - bar = arg(1, call_addr, 4)
```

- **Dependency Expressions:**
```yaml
where:
  - (a -> b) and (b -> c) and (not (a -> c))
  - (_anyarg -> a)
```
`_anyarg` refers to any argument of the current function.


This is the `where` expresions grammar:

```
<where>::= <assign> | <dep_expr>
<assign>::= <identifier> = <rv>
<rv>::= <deref> | <arg> | <identifier>
<deref>::= *<identifier>
<arg>::= arg(<integer>, <identifier>, <integer>)
<dep_expr>::= <dep>
            | <dep_expr> or <dep_expr>
            | <dep_expr> and <dep_expr>
            | not <dep_expr>
<dep>::= (<dep_var> -> <dep_var>)
<dep_var>::= <identifier> | _anyarg
```

### 5. Such-That

Lists logical constraints using variables from the `given` or `where` sections. Examples:

```yaml
such-that:
  - upper_unbounded(a + b)
  - (x + y) = 10
```

This is the `such-that` expressions grammar:

```
<such-that>::= <operand> and <operand>
             | <operand> or <operand>
             | not <operand>
             | <operand>
<operand>::= <eq> | <upper_unbounded>
<eq>::= <arith> = <arith>
<upper_unbounded>::= upper_unbounded(<arith>)
<arith>::= <integer> | <identifier>
         | <arith> * <arith>
         | <arith> / <arith>
         | <arith> + <arith>
         | <arith> - <arith>
```

### 6. Then

Indicates whether the analysis seeks a satisfiable state:

```yaml
then: True  # Default
```

### 7. Report

Specifies a message to be returned when a pattern is detected:

```yaml
report: "Suspicious behavior detected!"
```

## Examples

Example rule files can be found in the `test_files` directory. To see Dangr in action, try running the provided examples:

```bash
python dangr_c.py test_files/software_breakpoint.yaml
python test_files/software_breakpoint.py --binary-path /path/to/binary
```
