#Windows 9x VxD INT 20h annotator
#@author Drew Hoffman, ChatGPT Codex
#@category Windows
#@keybinding
#@menupath
#@toolbar
#@runtime PyGhidra

#
# Windows 9x VxD INT 20h annotator
#
# Replaces:
#
#   CD 20
#   xx xx
#   yy yy
#
# with:
#
#   INT 20
#   struct VxDCall {
#       WORD vxd_id;
#       WORD service_id;
#   }
#
# Adds comments and labels using decoded service names.
#

import re

from ghidra.program.model.data import (
    StructureDataType,
    WordDataType
)

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit

listing = currentProgram.getListing()
mem = currentProgram.getMemory()
dtm = currentProgram.getDataTypeManager()
symbol_table = currentProgram.getSymbolTable()

#
# ============================================================================
# Service database
# ============================================================================
#

SERVICES = {

    #
    # VMM (0001h)
    #

    (0x0001, 0x0000): "Get_VMM_Version",
    (0x0001, 0x0001): "Get_Cur_VM_Handle",
    (0x0001, 0x0002): "Test_Cur_VM_Handle",
    (0x0001, 0x0003): "Get_Sys_VM_Handle",
    (0x0001, 0x0004): "Test_Sys_VM_Handle",
    (0x0001, 0x0005): "Validate_VM_Handle",
    #...
    (0x0001, 0x004F): "_HeapAllocate",
    (0x0001, 0x0050): "_HeapReAllocate",
    (0x0001, 0x0051): "_HeapFree",

    (0x0001, 0x0053): "_PageAllocate",
    (0x0001, 0x0054): "_PageReAllocate",
    (0x0001, 0x0055): "_PageFree",

    (0x0001, 0x0090): "Hook_Device_Service",

    (0x0001, 0x012E): "_EnterMutex",
    (0x0001, 0x012F): "_LeaveMutex",
    
    # add remaining entries here
}

VXD_NAMES = {
    0x0001: "VMM",
    0x0002: "DEBUG",
    0x0003: "VPICD",
    0x0004: "VDMAD",
    0x0005: "VTD",
    0x0006: "V86MMGR",
    0x0007: "PAGESWAP",
    0x0009: "REBOOT",
    0x000A: "VDD",
    0x0015: "IFSMGR",
    # add more here
}

#
# ============================================================================
# Create / fetch structure type
# ============================================================================
#

STRUCT_NAME = "VxDCall"

vxdcall_struct = dtm.getDataType("/" + STRUCT_NAME)

if vxdcall_struct is None:

    vxdcall_struct = StructureDataType(STRUCT_NAME, 0)

    vxdcall_struct.add(
        WordDataType(),
        2,
        "vxd_id",
        None
    )

    vxdcall_struct.add(
        WordDataType(),
        2,
        "service_id",
        None
    )

    dtm.addDataType(vxdcall_struct, None)

#
# ============================================================================
# Helpers
# ============================================================================
#

def read_u16(addr):

    b0 = mem.getByte(addr) & 0xFF
    b1 = mem.getByte(addr.add(1)) & 0xFF

    return b0 | (b1 << 8)

def sanitize_name(name):

    #
    # Ghidra labels cannot contain some punctuation
    #

    name = re.sub(r'[^A-Za-z0-9_]', '_', name)

    #
    # Labels cannot start with a digit
    #

    if len(name) > 0 and name[0].isdigit():
        name = "_" + name

    return name

def remove_old_vxdcall_labels(addr):

    symbols = symbol_table.getSymbols(addr)

    for sym in symbols:

        name = sym.getName()

        if name.startswith("VxDCall_"):

            print(
                "Deleting old label at %s: %s"
                % (addr, name)
            )

            symbol_table.removeSymbolSpecial(sym)

#
# ============================================================================
# Main pass
# ============================================================================
#

instr_iter = listing.getInstructions(True)

count = 0

while instr_iter.hasNext() and not monitor.isCancelled():

    ins = instr_iter.next()

    #
    # Must be exactly: CD 20
    #

    bytes_ = ins.getBytes()

    if len(bytes_) != 2:
        continue

    if (bytes_[0] & 0xFF) != 0xCD:
        continue

    if (bytes_[1] & 0xFF) != 0x20:
        continue

    objs = ins.getOpObjects(0)

    if len(objs) == 0:
        continue

    try:
        value = objs[0].getValue()
    except:
        continue

    if value != 0x20:
        continue

    int_addr = ins.getAddress()

    #
    # 4-byte VxDCall payload immediately after INT
    #

    struct_addr = int_addr.add(2)

    try:

        vxd_id = read_u16(struct_addr)
        svc_id = read_u16(struct_addr.add(2))

    except:
        continue

    #
    # Remove only code/data units overlapping the 4-byte payload
    #

    for i in range(4):

        addr = struct_addr.add(i)

        cu = listing.getCodeUnitAt(addr)

        if cu is not None:

            cu_start = cu.getMinAddress()
            cu_end = cu.getMaxAddress()

            clearListing(cu_start, cu_end)

    #
    # Apply structure
    #

    try:
        createData(struct_addr, vxdcall_struct)
    except Exception as e:
        print(
            "Failed to apply structure at %s: %s"
            % (struct_addr, str(e))
        )
        continue
    
    #
    # Ensure disassembly resumes after payload
    #
    
    next_addr = struct_addr.add(4)

    disassemble(next_addr)
    
    #
    # Resolve names
    #

    vxd_name = VXD_NAMES.get(
        vxd_id,
        "VXD_%04X" % vxd_id
    )

    svc_name = SERVICES.get(
        (vxd_id, svc_id),
        "Service_%04X" % svc_id
    )

    full_name = "%s.%s" % (
        vxd_name,
        svc_name
    )

    #
    # Comments
    #

    ins.setComment(
        CodeUnit.EOL_COMMENT,
        "VxDCall %s" % full_name
    )

    ins.setComment(
        CodeUnit.REPEATABLE_COMMENT,
        full_name
    )

    #
    # Replace old auto labels
    #

    remove_old_vxdcall_labels(int_addr)

    #
    # Create new label
    #

    label_name = sanitize_name(
        "VxDCall_%s_%s" % (
            vxd_name,
            svc_name
        )
    )

    try:

        createLabel(
            int_addr,
            label_name,
            True
        )

    except Exception as e:

        print(
            "Failed creating label at %s: %s"
            % (int_addr, str(e))
        )

    print(
        "%s -> %s"
        % (int_addr, full_name)
    )

    count += 1

print("Processed %d VxD calls" % count)
