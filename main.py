import sys
import argparse

from assembler import Assembler

if __name__ == "__main__":
    asm = Assembler()

    input_path = ""
    output_path = ""
    parser = argparse.ArgumentParser()
    parser.add_argument("inputfile", type=str, help="input file path")
    parser.add_argument("-o", type=str, help="output file path", default="output.txt")

    args = parser.parse_args()
    if args.inputfile == "":
        print("Usage: python main.py <input_path> -o <output_path>")
        exit(1)

    input_path = args.inputfile

    output_path = args.o

    # run assembler
    asm.parser(input_path, output_path)
