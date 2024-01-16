import sys
import os
import argparse
import ast
import tokenize
from io import BytesIO


def remove_comments(source):
    tokens = tokenize.tokenize(BytesIO(source.encode('utf-8')).readline)
    
    filtered_tokens = [t for t in tokens if t.type == tokenize.COMMENT]
    result = tokenize.untokenize(filtered_tokens)
    return result

def parse_header(filename):
    with open(filename, 'r') as file:
        header_content = file.read()

    cleaned_header = remove_comments(header_content).replace("\\","").split("\n")
   
    macro_definitions = []
    
    for line in cleaned_header:
        if "#define" not in line:
            continue
        
        lr = line.replace("#define","").split()
        if len(lr) < 2:
            continue

        name_d = lr[0]
        v_d = lr[1]

        try:
            
            v_dd = 0
            if len(v_d) == 8:
                v_dd = int(v_d, 8)
            elif v_d.startswith("0x"):
                v_dd = int(v_d, 16)
            else:
                v_dd = int(v_d, 10)

            macro_definitions.append((v_dd, name_d))

        except Exception:
            continue

        


    
 
    return macro_definitions

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument("-i", "--input", help="C header file", required=True)
    parser.add_argument("-o", "--output", help="Output file")

    args = parser.parse_args()

    if not os.path.exists(args.input):
        print("[Error] Input file does not exist")
        sys.exit(1)

    macro_definitions = parse_header(args.input)

    # Print macro definitions
    for macro_value, macro_name in macro_definitions:
        print(f"{macro_value} {macro_name}")

if __name__ == "__main__":
    main()