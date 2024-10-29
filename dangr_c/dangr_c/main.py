import argparse
import os
from dangr_c.parser import DangrParser
from dangr_c.code_generator import DangrGenerator

def main():
    parser = argparse.ArgumentParser(description="Generate beheavorial pattern detector from a Dangr rule.")
    parser.add_argument("rule_file", type=str, help="Path to the YAML file containing the Dangr rule.")
    
    args = parser.parse_args()
    rule_path = args.rule_file
    
    if not os.path.isfile(rule_path):
        raise ValueError(f"Error: The file '{rule_path}' does not exist.")
    
    parser = DangrParser(rule_path)
    dangr_code_gen = parser.parse_dangr()
    
    generated_code = dangr_code_gen.generate_code()
    
    output_file = os.path.splitext(rule_path)[0] + ".py"
    
    with open(output_file, 'w') as file:
        file.write(generated_code)
    
if __name__ == "__main__":
    main()
