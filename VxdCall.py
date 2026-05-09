#@author Drew Hoffman, ChatGPT Codex
#@category Windows9x.VxD
#@keybinding
#@menupath
#@toolbar

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

from ghidra.program.model.address import Address
from ghidra.program.model.data import WordDataType
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType

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

    # VMM (0001h)
    (0x0001, 0x0000): "Get_VMM_Version",
    (0x0001, 0x0001): "Get_Cur_VM_Handle",
    (0x0001, 0x0002): "Test_Cur_VM_Handle",
    (0x0001, 0x0003): "Get_Sys_VM_Handle",
    (0x0001, 0x0004): "Test_Sys_VM_Handle",
    (0x0001, 0x0005): "Validate_VM_Handle",

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

monitor.initialize(currentProgram.getMemory().getNumAddresses())

instr = listing.getInstructions(True)

while instr.hasNext() and not monitor.isCancelled():

    ins = instr.next()

    # Check for "INT 20"
    if ins.getMnemonicString().upper() != "INT":
        continue

    ops = ins.getOpObjects(0)
    if len(ops) == 0:
        continue

    try:
        val = int(str(ops[0]), 0)
    except:
        continue

    if val != 0x20:
        continue

    int_addr = ins.getAddress()
    data_addr = int_addr.add(2)

    try:
        vxd_id = read_u16(data_addr)
        svc_id = read_u16(data_addr.add(2))
    except:
        continue

    # Clear incorrect disassembly/data
    clearListing(data_addr, data_addr.add(3))

    # Create WORD data items
    createData(data_addr, WordDataType())
    createData(data_addr.add(2), WordDataType())

    vxd_name = VXD_NAMES.get(vxd_id, "VXD_%04X" % vxd_id)

    svc_name = SERVICES.get(
        (vxd_id, svc_id),
        "Service_%04X" % svc_id
    )
    
    full_name = "%s.%s" % (vxd_name, svc_name)

    comment = "VxDCall %s" % full_name

    # comment = "VxDCall {} ({:04X}h), service {:04X}h".format(
    #    vxd_name,
    #    vxd_id,
    #    svc_id
    #)

    ins.setComment(CodeUnit.EOL_COMMENT, comment)
    try:
        # Optional label
        createLabel(
            int_addr,
            "VxDCall_{}_ {:04X}".format(vxd_name, svc_id).replace(" ", ""),
            True
        )
    except:
        pass

    print(
        "0x%s -> %s" %
        (int_addr, full_name)
    )

print("Done.")