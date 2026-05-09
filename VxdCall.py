#@author
#@category Windows9x.VxD
#@keybinding
#@menupath
#@toolbar

from ghidra.program.model.address import Address
from ghidra.program.model.data import WordDataType
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType

listing = currentProgram.getListing()
mem = currentProgram.getMemory()

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

def read_u16(addr):
    b0 = mem.getByte(addr) & 0xFF
    b1 = mem.getByte(addr.add(1)) & 0xFF
    return b0 | (b1 << 8)

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

    vxd_name = VXD_NAMES.get(vxd_id, "UNKNOWN")

    comment = "VxDCall {} ({:04X}h), service {:04X}h".format(
        vxd_name,
        vxd_id,
        svc_id
    )

    ins.setComment(CodeUnit.EOL_COMMENT, comment)

    # Optional label
    createLabel(
        int_addr,
        "VxDCall_{}_ {:04X}".format(vxd_name, svc_id).replace(" ", ""),
        True
    )

    print("0x{} -> {}".format(int_addr, comment))

print("Done.")