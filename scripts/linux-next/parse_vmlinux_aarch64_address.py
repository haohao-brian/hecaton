import sys
import re

class FuncClass:
    def __init__(self):
        self.name = ''
        self.base_addr = ''
        self.end_addr = ''
        self.base_line = 0
        self.end_line = 0
        self.frame_size = 0 # [NEW] Default 0 (will default to 16 in C if 0)
        
        # Init offsets to 100 (sentinel)
        self.x19 = 100; self.x20 = 100; self.x21 = 100; self.x22 = 100
        self.x23 = 100; self.x24 = 100; self.x25 = 100; self.x26 = 100
        self.x27 = 100; self.x28 = 100; self.x29 = 100; self.x30 = 100 

if len(sys.argv) != 4:
    print('usage: python parse_vmlinux_aarch64.py vmlinux.txt supported.txt hecaton_data.h')
    sys.exit(1)

vmlinux_path = sys.argv[1]
supp_path = sys.argv[2]
out_path = sys.argv[3]

try:
    with open(vmlinux_path, 'r') as f: lines = f.readlines()
    with open(supp_path, 'r') as f: supp_funcs = set(line.strip() for line in f)
except IOError as e: sys.exit(1)

functions = []

# --- 1. Identify Function Boundaries ---
print('Finding function boundaries...', file=sys.stderr)
i = 0
total_lines = len(lines)
while i < total_lines:
    line = lines[i]
    if ">:" in line:
        parts = line.split()
        if len(parts) < 2: 
            i+=1; continue
        func = FuncClass()
        func.name = parts[1].strip('<>:')
        func.base_addr = parts[0]
        func.base_line = i
        
        if ".cold" in func.name: 
            i+=1; continue
            
        # Find End
        curr = i + 1
        found_end = False
        while curr < total_lines:
            lc = lines[curr].strip()
            if lc == '' or ">:" in lines[curr] or '...' in lc:
                func.end_line = curr - 1
                while func.end_line > func.base_line and '...' in lines[func.end_line]: func.end_line -= 1
                end_parts = lines[func.end_line].split()
                func.end_addr = end_parts[0].rstrip(':') if end_parts else func.base_addr
                i = curr - 1 if ">:" in lines[curr] else curr
                found_end = True
                break
            curr += 1
        if not found_end: i = total_lines
        functions.append(func)
    i += 1

# --- 2. Parse Registers & Frame Size ---
print('Parsing stack frames...', file=sys.stderr)
# Regex for registers
reg_pattern = re.compile(r'^\s*[0-9a-fA-F]+:\s+(?:[0-9a-fA-F]+\s+)?(stp|str)\s+(x\d+),\s*(?:(x\d+),\s*)?\[sp,\s*#?((?:-?0x[0-9a-fA-F]+)|(?:-?\d+))\](!)?')
# Regex for Frame Size (sub sp, sp, #IMM)
sub_sp_pattern = re.compile(r'sub\s+sp,\s*sp,\s*#?((?:0x[0-9a-fA-F]+)|(?:\d+))')

target_regs = {'x19', 'x20', 'x21', 'x22', 'x23', 'x24', 'x25', 'x26', 'x27', 'x28', 'x29', 'x30'}

for f in functions:
    for ln in range(f.base_line, f.end_line + 1):
        line = lines[ln]
        if '\tret' in line or '\tb.' in line: break 

        # Check for Register Saves
        match = reg_pattern.search(line)
        if match:
            instr, reg1, reg2, offset_str, pre_index = match.groups()
            try: offset = int(offset_str, 0)
            except ValueError: continue

            # [NEW] Detect Frame Size from "stp ... [sp, #-48]!"
            if pre_index == '!':
                # The stack grew by the negative offset amount
                f.frame_size = abs(offset)
                base_offset = 0 # Relative to new SP
            else:
                base_offset = offset

            if reg1 in target_regs: setattr(f, reg1, base_offset)
            if instr == 'stp' and reg2 and reg2 in target_regs: setattr(f, reg2, base_offset + 8)

        # [NEW] Detect Frame Size from "sub sp, sp, #48"
        sub_match = sub_sp_pattern.search(line)
        if sub_match and f.frame_size == 0:
            try: f.frame_size = int(sub_match.group(1), 0)
            except ValueError: pass

print('Write outputs', file=sys.stderr)

# --- 3. Write Output ---
with open(out_path, 'w') as out:
    out.write("#ifndef __HECATON_DATA_FLAG\n#define __HECATON_DATA_FLAG\n")
    out.write(f"#define HECATON_ARRAY_SIZE\t{len(functions)}\n")
    out.write("#define HECATON_COLD_ARRAY_SIZE\t1\n")
    
    def write_arr(type, name, func):
        out.write(f"{type} {name}[HECATON_ARRAY_SIZE] = {{")
        for i, f in enumerate(functions):
            if i%10==0: out.write("\n")
            out.write(f"{func(f)}, ")
        out.write("};\n")

    write_arr("uint64_t", "hecaton_fnc_begin_addrs", lambda f: "0x"+f.base_addr if f.base_addr else "0x0")
    write_arr("uint64_t", "hecaton_fnc_end_addrs", lambda f: "0x"+f.end_addr if f.end_addr else "0x"+f.base_addr)
    
    # Write Frame Size
    write_arr("int16_t", "hecaton_frame_size", lambda f: str(f.frame_size))

    regs = ['x19','x20','x21','x22','x23','x24','x25','x26','x27','x28','x29','x30']
    for r in regs: write_arr("int16_t", f"hecaton_{r}", lambda f: getattr(f, r))
    
    write_arr("int8_t", "hecaton_supported", lambda f: "1" if f.name in supp_funcs else "0")
    
    out.write("uint64_t hecaton_cold_begin_addrs[1]={0};\nuint64_t hecaton_cold_begin_index[1]={0};\nuint64_t hecaton_cold_end_addrs[1]={0};\n#endif\n")
