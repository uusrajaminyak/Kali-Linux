from triton import *
import sys
import re

ctx = TritonContext(ARCH.X86_64)
ast = ctx.getAstContext()
input_sym = ctx.newSymbolicVariable(64, "input")
input_node = ast.variable(input_sym)

print(f"[+] Symbolic variable created: {input_node}")

bytecode = [
    0x10, 0x00,
    0x20, 0x05,
    0x40, 0x2D,
    0xFF
]

pc = 0
reg_acc = ast.bv(0, 64)
running = True

print("[+] Starting translating bytecode to logical formula...")

while running:
    opcode = bytecode[pc]
    pc += 1

    if opcode == 0x10:  
        reg_acc = input_node
        pc += 1

    elif opcode == 0x20:  
        arg = bytecode[pc]
        reg_acc = ast.bvadd(reg_acc, ast.bv(arg, 64))
        pc += 1

    elif opcode == 0x30:  
        arg = bytecode[pc]
        reg_acc = ast.bvsub(reg_acc, ast.bv(arg, 64))
        pc += 1

    elif opcode == 0x40:  
        arg = bytecode[pc]
        reg_acc = ast.bvxor(reg_acc, ast.bv(arg, 64))
        pc += 1

    elif opcode == 0xFF:  
        running = False

    else:
        print(f"[-] Unknown opcode {opcode} at pc {pc}")
        sys.exit(1)

print("[+] Bytecode translation completed.")
print("Raw formula:")
print(reg_acc)

print("[+] Simplifying formula...")
simplified = ctx.simplify(reg_acc)
print("Simplified formula:")
print(simplified)

str_formula = str(simplified)
str_formula = str_formula.replace("bvadd", "+").replace("bvsub", "-").replace("bvxor", "^")
str_formula = re.sub(r'\(_ bv(\d+) 64\)', r'\1', str_formula)

print("Human readable formula:")
print(str_formula)