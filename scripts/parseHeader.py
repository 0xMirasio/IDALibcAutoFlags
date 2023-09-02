import sys
import os
import argparse

parser = argparse.ArgumentParser()

parser.add_argument("-i", "--input", help="C header file", required=True)
parser.add_argument("-o", "--output", help="Output file")

args = parser.parse_args()

if not os.path.exists(args.input):
    print("[Error] Input file does not exist")
    sys.exit(1)

headerFile = open(args.input,"r").readlines()

toSave = {}
for line in headerFile:
    data = line.strip()
    if "#define" in data or "# define" in data:
        data = data.replace("#define","").replace("# define","").split()
        if len(data) > 1:
            if data[0] in toSave:
                print("[Warning] Key {0} already exists in dictionary".format(data[0]))

            try:

                if "0x" in data[1]:
                    data[1] = str(int(data[1].replace("0x",""),16))
                else:
                    data[1] = str(int(data[1]))
                
                toSave[data[0]] = data[1]

            except Exception:
                pass

print("Result : ")
for key in toSave:
    print("{1} {0}".format(key,toSave[key]))

if args.output:
    with open(args.output, 'w') as fd:
        for key in toSave:
            data = f"{toSave[key]} {key}\n"
            fd.write(data)

    fd.close()

        