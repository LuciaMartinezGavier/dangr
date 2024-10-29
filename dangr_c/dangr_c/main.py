import argparse
import os
from dangr_c.parser import DangrParser

def main() -> None:
    arg_parser = argparse.ArgumentParser(
        description="Generate beheavorial pattern detector from a Dangr rule."
    )

    arg_parser.add_argument(
        "rule_file", type=str,
        help="Path to the YAML file containing the Dangr rule."
    )

    args = arg_parser.parse_args()
    rule_path = args.rule_file

    if not os.path.isfile(rule_path):
        raise ValueError(f"Error: The file '{rule_path}' does not exist.")

    dangr_parser = DangrParser(rule_path)
    dangr_code_gen = dangr_parser.parse_dangr()

    generated_code = dangr_code_gen.generate_code()

    output_file = os.path.splitext(rule_path)[0] + ".py"

    with open(output_file, 'w', encoding='utf-8') as file:
        file.write(generated_code)

if __name__ == "__main__":
    main()
