# @runtime Jython
# @category: Windows9x
# @author Drew Hoffman, ChatGPT Codex, Google Gemini  
# @toolbar
import os
from ghidra.program.model.symbol import SourceType

def import_segmented_map(file_path):
    if not os.path.exists(file_path):
        print("Symbol file not found: " + file_path)
        return

    current_program = getCurrentProgram()
    addr_factory = current_program.getAddressFactory()
    listing = current_program.getListing()
    
    success_count = 0
    fail_count = 0

    with open(file_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            raw_line = line
            line = line.strip()
            
            # Skip empty lines, comment headers, or section banners
            if not line or line.startswith(';') or 'Publics by Name' in line:
                continue
            
            parts = line.split()
            if len(parts) < 2:
                print("Line {}: Skipped (not enough parts): '{}'".format(line_num, raw_line.strip()))
                fail_count += 1
                continue

            # In the sample MAP format provided, the address is the FIRST token, and the symbol name is the SECOND token.
            # Example: 0001:00000000    VMD_Control
            addr_str = parts[0]
            sym_name = parts[1]

            try:
                # Parse segment:offset format (e.g., 0001:000004e4)
                if ":" in addr_str:
                    seg_str, off_str = addr_str.split(":")
                    seg = int(seg_str, 16)
                    off = int(off_str, 16)
                    
                    # Apply linear calculation: (segment << 20) + offset
                    linear_addr = (seg << 20) + off
                    addr = addr_factory.getDefaultAddressSpace().getAddress(format(linear_addr, 'x'))
                else:
                    addr = toAddr(addr_str)

                if addr:
                    block = current_program.getMemory().getBlock(addr)
                    if not block:
                        print("Line {}: Address {} ({}) falls outside loaded memory blocks.".format(line_num, addr, addr_str))
                        fail_count += 1
                        continue

                    # Check if instruction exists; if not, attempt disassembly
                    instr = listing.getInstructionAt(addr)
                    if not instr:
                        disassemble(addr)

                    # Create or update the label with user-defined precedence
                    createLabel(addr, sym_name, True, SourceType.USER_DEFINED)
                    
                    # Ensure function creation if code is present
                    existing_func = listing.getFunctionAt(addr)
                    if not existing_func and listing.getInstructionAt(addr):
                        createFunction(addr, sym_name)
                    elif existing_func:
                        existing_func.setName(sym_name, SourceType.USER_DEFINED)

                    success_count += 1
                else:
                    print("Line {}: Could not resolve address from string '{}'".format(line_num, addr_str))
                    fail_count += 1
            except Exception as e:
                print("Line {} error on line '{}': {}".format(line_num, raw_line.strip(), e))
                fail_count += 1

    print("Import complete. Successfully imported: {}, Failed: {}".format(success_count, fail_count))

symbol_file = askFile("Select Segmented Map File", "Import")
if symbol_file:
    import_segmented_map(symbol_file.absolutePath)