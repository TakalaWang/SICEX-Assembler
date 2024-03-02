import json
import re

opcode_table = json.load(open("table/opcode.json", "r"))
directive_table = json.load(open("table/directive.json", "r"))
register_table = json.load(open("table/register.json", "r"))


class Instruction:
    def __init__(
        self, index: int, format: int, symbol: str, mnemonic: str, operand: str
    ) -> None:
        self.index = index
        self.format = format
        self.symbol = symbol
        self.mnemonic = mnemonic
        self.operand = operand
        self.location = None
        self.object_code = ""

    def __str__(self) -> str:
        location = hex(self.location) if self.location != None else self.location
        return f"({self.index}, {self.format}, {self.symbol}, {self.mnemonic}, {self.operand}, {location}, {self.object_code})"


class Modification_record:
    def __init__(
        self, location: int, length: int, sign: str = "", reference: str = ""
    ) -> None:
        self.location = location
        self.length = length
        self.sign = sign
        self.reference = reference

    def __str__(self) -> str:
        return f"({self.location}, {self.length}, {self.sign}, {self.reference})"


class Section:
    def __init__(self) -> None:
        self.instructions = []
        self.__extdef_table = {}
        self.__extref_table = {}
        self.__modified_record = []
        self.__symbol_table = {}

    def __str__(self) -> str:
        print("Symbol{")
        for symbol in self.__symbol_table:
            print("\t", symbol, self.__symbol_table[symbol])
        print("}\n")
        # print each extdef
        print("Extdef{")
        for d in self.__extdef_table:
            print("\t", d, self.__extdef_table[d])
        print("}\n")
        # print each extref
        print("Extref{")
        for r in self.__extref_table:
            print("\t", r, self.__extref_table[r])
        print("}\n")
        # print each modified record
        print("Modified{")
        for record in self.__modified_record:
            print("\t", record)
        print("}\n")
        # print instruction
        print("Instructions:")
        for insruction in self.instructions:
            print("\t", insruction)
        print("\n")
        return ""

    def _calculate(self, operand: str, cur_location: int, mnemonic: str) -> str:
        if operand == "*":
            operand = str(cur_location)
            return operand
        for symbol in self.__symbol_table:
            if symbol in operand and self.__symbol_table[symbol] != None:
                operand = operand.replace(symbol, str(self.__symbol_table[symbol]))
        for symbol in self.__extref_table:
            if symbol in operand and self.__extref_table[symbol] != None:
                m = operand.find(symbol)
                operand = operand.replace(symbol, str(self.__extref_table[symbol]))
                if m - 1 >= 0:
                    sign = "+" if operand[m - 1] == "+" else "-"
                else:
                    sign = "+"
                have = False
                for record in self.__modified_record:
                    if (
                        record.location == cur_location + 1
                        and record.reference == symbol
                    ):
                        have = True
                        break
                if have:
                    continue

                self.__modified_record.append(
                    Modification_record(
                        cur_location + 1, 6 if mnemonic == "WORD" else 5, sign, symbol
                    )
                )

        try:
            result = eval(operand)
            return result
        except:
            return None

    def solve_literal(self) -> None:
        literal_table = []
        literal_count = 1
        literal_set = {}

        for index, instruction in enumerate(self.instructions):
            if instruction.operand != "":
                if instruction.mnemonic == "*":
                    instruction.mnemonic = "BYTE"
                if instruction.operand[0] == "=":
                    if instruction.operand in literal_set:
                        instruction.operand = literal_set[instruction.operand]
                    else:
                        literal_table.append(
                            {
                                "name": "literal" + str(literal_count),
                                "data": instruction.operand[1:],
                            }
                        )
                        literal_set[instruction.operand] = "literal" + str(
                            literal_count
                        )
                        instruction.operand = "literal" + str(literal_count)
                        literal_count += 1

            elif instruction.mnemonic == "LTORG" or instruction.mnemonic == "END":
                for literal in literal_table[::-1]:
                    literal_instercution = Instruction(
                        -1, 0, literal["name"], "BYTE", literal["data"]
                    )
                    self.instructions.insert(index, literal_instercution)
                literal_table = []

    def sorting_block(self) -> None:
        defalut_block = ""
        blocks = {}
        blocks_premutation = []
        cur_block = None
        end = None
        for index, instruction in enumerate(self.instructions):
            if instruction.mnemonic == "START":
                defalut_block = instruction.symbol
                blocks[instruction.symbol] = []
                cur_block = instruction.symbol
                if cur_block not in blocks_premutation:
                    blocks_premutation.append(cur_block)
            elif instruction.mnemonic == "CSECT":
                blocks[instruction.symbol] = []
                cur_block = instruction.symbol
                if cur_block not in blocks_premutation:
                    blocks_premutation.append(cur_block)
            elif instruction.mnemonic == "USE":
                if instruction.operand == "":
                    cur_block = defalut_block
                elif instruction.operand not in blocks_premutation:
                    cur_block = instruction.operand
                    blocks[cur_block] = []
                    blocks_premutation.append(cur_block)
                else:
                    cur_block = instruction.operand
            elif instruction.mnemonic == "END":
                end = instruction
                continue

            blocks[cur_block].append(instruction)
            instruction.index = index

        self.instructions = []
        for block in blocks_premutation:
            for instruction in blocks[block]:
                self.instructions.append(instruction)

        end.index = max(self.instructions, key=lambda x: x.index).index + 1
        self.instructions.append(end)

    def set_symbol(self) -> None:
        for instruction in self.instructions:
            if instruction.symbol != "":
                self.__symbol_table[instruction.symbol] = None
            if instruction.mnemonic == "EXTDEF":
                for symbol in instruction.operand.split(","):
                    self.__extdef_table[symbol] = None
            if instruction.mnemonic == "EXTREF":
                for symbol in instruction.operand.split(","):
                    self.__extref_table[symbol] = 0

        while True:
            finished = True
            for symbol in self.__symbol_table:
                if self.__symbol_table[symbol] == None:
                    finished = False
                    break
            if finished:
                break

            cur_location = 0

            for instruction in self.instructions:
                if instruction.symbol != "":
                    self.__symbol_table[instruction.symbol] = cur_location
                    if instruction.symbol in self.__extdef_table:
                        self.__extdef_table[instruction.symbol] = cur_location

                if instruction.mnemonic == "START":
                    cur_location = int(instruction.operand, 16)
                    self.__symbol_table[instruction.symbol] = int(
                        instruction.operand, 16
                    )
                elif instruction.mnemonic == "CSECT":
                    cur_location = 0
                    self.__symbol_table[instruction.symbol] = 0
                elif instruction.mnemonic == "RESW":
                    self.__symbol_table[instruction.symbol] = cur_location
                    result = self._calculate(
                        instruction.operand, cur_location, instruction.mnemonic
                    )
                    if result == None:
                        continue
                    cur_location += 3 * int(result)
                elif instruction.mnemonic == "RESB":
                    self.__symbol_table[instruction.symbol] = cur_location
                    result = self._calculate(
                        instruction.operand, cur_location, instruction.mnemonic
                    )
                    if result == None:
                        continue
                    cur_location += int(result)
                elif instruction.mnemonic == "BYTE":
                    self.__symbol_table[instruction.symbol] = cur_location
                    if instruction.operand[0] == "C":
                        cur_location += len(instruction.operand) - 3
                    elif instruction.operand[0] == "X":
                        cur_location += (len(instruction.operand) - 3) // 2
                elif instruction.mnemonic == "WORD":
                    result = self._calculate(
                        instruction.operand, cur_location, instruction.mnemonic
                    )
                    if result != None:
                        self.__symbol_table[instruction.symbol] = result
                    cur_location += 3
                elif instruction.mnemonic == "EQU":
                    result = self._calculate(
                        instruction.operand, cur_location, instruction.mnemonic
                    )
                    if result != None:
                        self.__symbol_table[instruction.symbol] = result
                elif instruction.mnemonic == "ORG":
                    result = self._calculate(
                        instruction.operand, cur_location, instruction.mnemonic
                    )
                    if result != None:
                        instruction.operand = result
                        cur_location = (int(result),)
                    else:
                        raise Exception("ORG can't support forward reference")
                elif instruction.mnemonic == "BASE":
                    result = self._calculate(
                        instruction.operand, cur_location, instruction.mnemonic
                    )
                    if result != None:
                        instruction.operand = result
                elif instruction.mnemonic == "RSUB":
                    instruction.operand = "#0"
                    cur_location += 3
                else:
                    cur_location += int(instruction.format)

    def set_location(self) -> None:
        cur_location = 0
        for instruction in self.instructions:
            instruction.location = cur_location
            cur_location += int(instruction.format)
            if instruction.mnemonic == "START":
                instruction.location = int(instruction.operand, 16)
                cur_location = int(instruction.operand, 16)
            elif instruction.mnemonic == "CSECT":
                instruction.location = 0
                cur_location = 0
            elif instruction.mnemonic == "RESW":
                result = self._calculate(
                    instruction.operand, cur_location, instruction.mnemonic
                )
                cur_location += 3 * int(result)
            elif instruction.mnemonic == "RESB":
                result = self._calculate(
                    instruction.operand, cur_location, instruction.mnemonic
                )
                cur_location += int(result)
            elif instruction.mnemonic == "BYTE":
                if instruction.operand[0] == "C":
                    cur_location += len(instruction.operand) - 3
                elif instruction.operand[0] == "X":
                    cur_location += (len(instruction.operand) - 3) // 2
            elif instruction.mnemonic == "WORD":
                cur_location += 3
            elif instruction.mnemonic == "ORG":
                result = self._calculate(
                    instruction.operand, cur_location, instruction.mnemonic
                )
                cur_location = int(result)

    def set_exdef_location(self) -> None:
        for symbol in self.__extdef_table:
            self.__extdef_table[symbol] = self.__symbol_table[symbol]

    def sorting_index(self) -> None:
        self.instructions.sort(key=lambda x: x.index)

    def generate_object_code(self) -> None:
        base = 0
        for instruction in self.instructions:
            if instruction.mnemonic == "BYTE":
                if instruction.operand[0] == "C":
                    for char in instruction.operand[2:-1]:
                        instruction.object_code += f"{ord(char):02X}"
                elif instruction.operand[0] == "X":
                    instruction.object_code = instruction.operand[2:-1]
            elif instruction.mnemonic == "WORD":
                instruction.object_code = f"{int(self._calculate(instruction.operand, instruction.location, instruction.mnemonic)):06X}"
            elif instruction.mnemonic == "BASE":
                base = self._calculate(
                    instruction.operand, instruction.location, instruction.mnemonic
                )
            elif instruction.mnemonic == "RSUB":
                instruction.object_code = "4F0000"
            elif instruction.mnemonic in opcode_table:
                if instruction.format == 1:
                    instruction.object_code = (
                        f"{opcode_table[instruction.mnemonic]['obj']}"
                    )
                elif instruction.format == 2:
                    register1 = register_table[instruction.operand.split(",")[0]]
                    register2 = register_table[
                        (
                            instruction.operand.split(",")[1]
                            if len(instruction.operand.split(",")) > 1
                            else "A"
                        )
                    ]
                    instruction.object_code = f"{opcode_table[instruction.mnemonic]['obj']}{register1}{register2}"
                elif instruction.format == 3:
                    opcode = int(opcode_table[instruction.mnemonic]["obj"], 16) >> 2
                    n, i, x, b, p, e = 0, 0, 0, 0, 0, 0
                    disp = 0
                    if "," in instruction.operand:
                        x = 1
                        instruction.operand = instruction.operand[:-2]
                    if instruction.operand[0] == "#":
                        if instruction.operand[1:].isdigit():
                            n, i, b, p = 0, 1, 0, 0
                            disp = int(
                                self._calculate(
                                    instruction.operand[1:],
                                    instruction.location,
                                    instruction.mnemonic,
                                )
                            )
                            code = f"{opcode:>06b}{n}{i}{x}{b}{p}{e}{disp:>012b}"
                            instruction.object_code = f"{int(code,2):>06X}"
                        else:
                            n, i = 0, 1
                            TA = int(
                                self._calculate(
                                    instruction.operand[1:],
                                    instruction.location,
                                    instruction.mnemonic,
                                )
                            )
                            if (
                                -(2**11)
                                <= TA - (instruction.location + instruction.format)
                                <= 2**11 - 1
                            ):
                                b, p = 0, 1
                                disp = TA - (instruction.location + instruction.format)
                                if disp < 0:
                                    disp = 2**12 + disp
                                code = f"{opcode:>06b}{n}{i}{x}{b}{p}{e}{disp:>012b}"
                                instruction.object_code = f"{int(code,2):>06X}"
                            elif 0 <= TA - base <= 2**12 - 1:
                                b, p = 1, 0
                                disp = TA - base
                                code = f"{opcode:>06b}{n}{i}{x}{b}{p}{e}{disp:>012b}"
                                instruction.object_code = f"{int(code,2):>06X}"
                            else:
                                print("ERROR: ", instruction)
                                raise Exception("Error: ", instruction, "Need format 4")

                    elif instruction.operand[0] == "@":
                        n, i = 1, 0
                        TA = int(
                            self._calculate(
                                instruction.operand[1:],
                                instruction.location,
                                instruction.mnemonic,
                            )
                        )

                        if (
                            -(2**11)
                            <= TA - (instruction.location + instruction.format)
                            <= 2**11 - 1
                        ):
                            b, p = 0, 1
                            disp = TA - (instruction.location + instruction.format)
                            if disp < 0:
                                disp = 2**12 + disp
                            code = f"{opcode:>06b}{n}{i}{x}{b}{p}{e}{disp:>012b}"
                            instruction.object_code = f"{int(code,2):>06X}"
                        elif 0 <= TA - base <= 2**12 - 1:
                            b, p = 1, 0
                            disp = TA - base
                            code = f"{opcode:>06b}{n}{i}{x}{b}{p}{e}{disp:>012b}"
                            instruction.object_code = f"{int(code,2):>06X}"
                        else:
                            print("ERROR: ", instruction)
                            raise Exception("Error: ", instruction, "Need format 4")
                    else:
                        n, i = 1, 1
                        TA = int(
                            self._calculate(
                                instruction.operand,
                                instruction.location,
                                instruction.mnemonic,
                            )
                        )
                        if (
                            -(2**11)
                            <= TA - (instruction.location + instruction.format)
                            <= 2**11 - 1
                        ):
                            b, p = 0, 1
                            disp = TA - (instruction.location + instruction.format)
                            if disp < 0:
                                disp = 2**12 + disp
                            code = f"{opcode:>06b}{n}{i}{x}{b}{p}{e}{disp:>012b}"
                            instruction.object_code = f"{int(code,2):>06X}"
                        elif 0 <= TA - base <= 2**12 - 1:
                            b, p = 1, 0
                            disp = TA - base
                            code = f"{opcode:>06b}{n}{i}{x}{b}{p}{e}{disp:>012b}"
                            instruction.object_code = f"{int(code,2):>06X}"
                        else:
                            print("ERROR: ", instruction)
                            raise Exception("Error: ", instruction, "Need format 4")
                elif instruction.format == 4:
                    opcode = int(opcode_table[instruction.mnemonic]["obj"], 16) >> 2
                    n, i, x, b, p, e = 0, 0, 0, 0, 0, 1
                    disp = 0
                    if "," in instruction.operand:
                        x = 1
                        instruction.operand = instruction.operand[:-2]
                    if instruction.operand[0] == "#":
                        n, i, b, p = 0, 1, 0, 0
                        disp = int(
                            self._calculate(
                                instruction.operand[1:],
                                instruction.location,
                                instruction.mnemonic,
                            )
                        )
                        code = f"{opcode:>06b}{n}{i}{x}{b}{p}{e}{disp:>020b}"
                        instruction.object_code = f"{int(code,2):>08X}"
                    else:
                        n, i, b, p = 1, 1, 0, 0
                        disp = int(
                            self._calculate(
                                instruction.operand,
                                instruction.location,
                                instruction.mnemonic,
                            )
                        )
                        code = f"{opcode:>06b}{n}{i}{x}{b}{p}{e}{disp:>020b}"
                        instruction.object_code = f"{int(code,2):>08X}"

                        have = False
                        for record in self.__modified_record:
                            if (
                                record.location == instruction.location + 1
                                and record.reference == instruction.operand
                            ):
                                have = True
                                break
                        if have:
                            continue
                        self.__modified_record.append(
                            Modification_record(instruction.location + 1, 5)
                        )

    def assemble(self) -> None:
        self.solve_literal()
        self.sorting_block()
        self.set_symbol()
        self.set_location()
        self.set_exdef_location()
        self.sorting_index()
        self.generate_object_code()

    def write(self, file) -> None:
        # write header
        file.write("H")
        file.write(self.instructions[0].symbol.ljust(6))
        file.write(f"{self.instructions[0].location:06X}")
        file.write(
            f"{self.instructions[-1].location - self.instructions[0].location:06X}"
        )
        file.write("\n")

        # write extdef
        size = 0
        for symbol in self.__extdef_table:
            if size == 0:
                file.write("D")
            file.write(symbol.ljust(6))
            file.write(f"{int(self.__extdef_table[symbol]):06X}")
            size += 1
            if size == 5:
                file.write("\n")
                size = 0
        if self.__extdef_table != {}:
            file.write("\n")

        # write extref
        size = 0
        for symbol in self.__extref_table:
            if size == 0:
                file.write("R")
            file.write(symbol.ljust(6))
            size += 1
            if size == 5:
                file.write("\n")
                size = 0
        if self.__extref_table != {}:
            file.write("\n")

        cur_start = ""
        cur_text = ""
        for instruction in self.instructions:
            if (
                instruction.mnemonic == "RESW"
                or instruction.mnemonic == "RESB"
                or instruction.mnemonic == "USE"
            ):
                if cur_text != "":
                    file.write("T")
                    file.write(f"{cur_start:06X}")
                    file.write(f"{len(cur_text)//2:02X}")
                    file.write(cur_text)
                    file.write("\n")
                    cur_text = ""
                continue
            if cur_text == "":
                cur_start = instruction.location
            if len(cur_text) + len(instruction.object_code) > 60:
                file.write("T")
                file.write(f"{cur_start:06X}")
                file.write(f"{len(cur_text)//2:02X}")
                file.write(cur_text)
                file.write("\n")
                cur_text = ""
                cur_start = instruction.location
            cur_text += instruction.object_code
        if cur_text != "":
            file.write("T")
            file.write(f"{cur_start:06X}")
            file.write(f"{len(cur_text)//2:02X}")
            file.write(cur_text)
            file.write("\n")

        # write modified record
        self.__modified_record.sort(key=lambda x: x.location)
        for record in self.__modified_record:
            file.write("M")
            file.write(f"{record.location:06X}")
            file.write(f"{record.length:02X}")
            file.write(record.sign)
            file.write(record.reference)
            file.write("\n")

        # write end
        file.write("E")
        if self.instructions[0].mnemonic == "START":
            file.write(f"{self.instructions[0].location:06X}")

        file.write("\n\n")


class Assembler:
    def __init__(self) -> None:
        self.__instructions = []
        self.__sections = []

    def clear(self) -> None:
        self.__instructions = []
        self.__sections = []

    def preprocessing(self, path: str) -> None:
        with open(path, "r") as f:
            for line in f.readlines():
                if line.strip() == "":
                    continue
                line = line.strip().replace("\t", " ").split()
                line += [""] * (3 - len(line))
                if line[1] == "BYTE":
                    for i in range(3, len(line)):
                        line[2] += " " + line[i]
                line[2].strip()

                instruction = Instruction(-1, 0, "", "", "")

                if "." in line[0]:
                    continue

                if "+" in line[0]:
                    instruction.format = 4
                    line[0] = line[0].replace("+", "")
                elif "+" in line[1]:
                    instruction.format = 4
                    line[1] = line[1].replace("+", "")

                if (
                    line[0] in opcode_table
                    or line[0] in directive_table
                    or line[0] == "*"
                ):
                    line[2] = line[1]
                    line[1] = line[0]
                    line[0] = ""

                instruction.symbol = line[0]
                instruction.mnemonic = line[1]
                instruction.operand = line[2]

                if instruction.format != 4 and instruction.mnemonic in opcode_table:
                    instruction.format = opcode_table[instruction.mnemonic]["format"]
                elif instruction.format != 4:
                    instruction.format = 0

                self.__instructions.append(instruction)

        self.__sections.append(Section())
        for instruction in self.__instructions:
            if instruction.mnemonic == "END":
                self.__sections[0].instructions.append(instruction)
                break
            if instruction.mnemonic == "CSECT":
                self.__sections.append(Section())
            self.__sections[-1].instructions.append(instruction)
        for section in self.__sections[1:]:
            section.instructions.append(Instruction(-1, 0, "", "END", ""))

    def assemble(self) -> None:
        for index, section in enumerate(self.__sections):
            print("SECTION", index, ":")
            section.assemble()
            print(section)

    def write_file(self, path: str) -> None:
        for index, section in enumerate(self.__sections):
            with open(path + "-" + str(index + 1) + ".txt", "w") as f:
                section.write(f)

    def parser(self, input_path: str, output_path: str) -> None:
        self.clear()
        self.preprocessing(input_path)
        self.assemble()
        self.write_file(output_path)
