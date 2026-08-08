# @runtime Jython
#@author Drew Hoffman, ChatGPT Codex, Google Gemini 
#@category Windows9x
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
#       WORD service_id;
#       WORD vxd_id;
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
from ghidra.program.model.address import AddressSet

listing = currentProgram.getListing()
mem = currentProgram.getMemory()
dtm = currentProgram.getDataTypeManager()
symbol_table = currentProgram.getSymbolTable()

#
# ============================================================================
# Services database
# Generated / compiled from:
# vmm.h in Windows 98 DDK
# vmm.h in VMDisp9x by Jaroslav Hensl (JHRobotics)
# and Ralf Brown's Interrupt List at http://www.ctyme.com/intr/int-20.htm
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

    (0x0001, 0x0006): "Get_VMM_Reenter_Count",
    (0x0001, 0x0007): "Begin_Reentrant_Execution",
    (0x0001, 0x0008): "End_Reentrant_Execution",

    (0x0001, 0x0009): "Install_V86_Break_Point",
    (0x0001, 0x000A): "Remove_V86_Break_Point",
    (0x0001, 0x000B): "Allocate_V86_Call_Back",
    (0x0001, 0x000C): "Allocate_PM_Call_Back",

    (0x0001, 0x000D): "Call_When_VM_Returns",

    (0x0001, 0x000E): "Schedule_Global_Event",
    (0x0001, 0x000F): "Schedule_VM_Event",
    (0x0001, 0x0010): "Call_Global_Event",
    (0x0001, 0x0011): "Call_VM_Event",
    (0x0001, 0x0012): "Cancel_Global_Event",
    (0x0001, 0x0013): "Cancel_VM_Event",
    (0x0001, 0x0014): "Call_Priority_VM_Event",
    (0x0001, 0x0015): "Cancel_Priority_VM_Event",

    (0x0001, 0x0016): "Get_NMI_Handler_Addr",
    (0x0001, 0x0017): "Set_NMI_Handler_Addr",
    (0x0001, 0x0018): "Hook_NMI_Event",

    (0x0001, 0x0019): "Call_When_VM_Ints_Enabled",
    (0x0001, 0x001A): "Enable_VM_Ints",
    (0x0001, 0x001B): "Disable_VM_Ints",

    (0x0001, 0x001C): "Map_Flat",
    (0x0001, 0x001D): "Map_Lin_To_VM_Addr",

    # Scheduler services

    (0x0001, 0x001E): "Adjust_Exec_Priority",
    (0x0001, 0x001F): "Begin_Critical_Section",
    (0x0001, 0x0020): "End_Critical_Section",
    (0x0001, 0x0021): "End_Crit_And_Suspend",
    (0x0001, 0x0022): "Claim_Critical_Section",
    (0x0001, 0x0023): "Release_Critical_Section",
    (0x0001, 0x0024): "Call_When_Not_Critical",
    (0x0001, 0x0025): "Create_Semaphore",
    (0x0001, 0x0026): "Destroy_Semaphore",
    (0x0001, 0x0027): "Wait_Semaphore",
    (0x0001, 0x0028): "Signal_Semaphore",
    (0x0001, 0x0029): "Get_Crit_Section_Status",
    (0x0001, 0x002A): "Call_When_Task_Switched",
    (0x0001, 0x002B): "Suspend_VM",
    (0x0001, 0x002C): "Resume_VM",
    (0x0001, 0x002D): "No_Fail_Resume_VM",
    (0x0001, 0x002E): "Nuke_VM",
    (0x0001, 0x002F): "Crash_Cur_VM",

    (0x0001, 0x0030): "Get_Execution_Focus",
    (0x0001, 0x0031): "Set_Execution_Focus",
    (0x0001, 0x0032): "Get_Time_Slice_Priority",
    (0x0001, 0x0033): "Set_Time_Slice_Priority",
    (0x0001, 0x0034): "Get_Time_Slice_Granularity",
    (0x0001, 0x0035): "Set_Time_Slice_Granularity",
    (0x0001, 0x0036): "Get_Time_Slice_Info",
    (0x0001, 0x0037): "Adjust_Execution_Time",
    (0x0001, 0x0038): "Release_Time_Slice",
    (0x0001, 0x0039): "Wake_Up_VM",
    (0x0001, 0x003A): "Call_When_Idle",

    (0x0001, 0x003B): "Get_Next_VM_Handle",

    # Time-out and system timer services

    (0x0001, 0x003C): "Set_Global_Time_Out",
    (0x0001, 0x003D): "Set_VM_Time_Out",
    (0x0001, 0x003E): "Cancel_Time_Out",
    (0x0001, 0x003F): "Get_System_Time",
    (0x0001, 0x0040): "Get_VM_Exec_Time",

    (0x0001, 0x0041): "Hook_V86_Int_Chain",
    (0x0001, 0x0042): "Get_V86_Int_Vector",
    (0x0001, 0x0043): "Set_V86_Int_Vector",
    (0x0001, 0x0044): "Get_PM_Int_Vector",
    (0x0001, 0x0045): "Set_PM_Int_Vector",

    (0x0001, 0x0046): "Simulate_Int",
    (0x0001, 0x0047): "Simulate_Iret",
    (0x0001, 0x0048): "Simulate_Far_Call",
    (0x0001, 0x0049): "Simulate_Far_Jmp",
    (0x0001, 0x004A): "Simulate_Far_Ret",
    (0x0001, 0x004B): "Simulate_Far_Ret_N",
    (0x0001, 0x004C): "Build_Int_Stack_Frame",

    (0x0001, 0x004D): "Simulate_Push",
    (0x0001, 0x004E): "Simulate_Pop",

    # Heap Manager
    (0x0001, 0x004F): "HeapAllocate",
    (0x0001, 0x0050): "HeapReAllocate",
    (0x0001, 0x0051): "HeapFree",
    (0x0001, 0x0052): "HeapGetSize",

    #
    # Flags for heap allocator calls
    #
    # NOTE: HIGH 8 BITS (bits 24-31) are reserved
    #
    # HEAPZEROINIT   = 0x00000001
    # HEAPZEROREINIT = 0x00000002
    # HEAPNOCOPY     = 0x00000004
    # HEAPLOCKEDIFDP = 0x00000100
    # HEAPSWAP       = 0x00000200
    # HEAPINIT       = 0x00000400
    # HEAPCLEAN      = 0x00000800

    # Page Manager

    (0x0001, 0x0053): "PageAllocate",
    (0x0001, 0x0054): "PageReAllocate",
    (0x0001, 0x0055): "PageFree",
    (0x0001, 0x0056): "PageLock",
    (0x0001, 0x0057): "PageUnLock",
    (0x0001, 0x0058): "PageGetSizeAddr",
    (0x0001, 0x0059): "PageGetAllocInfo",
    (0x0001, 0x005A): "GetFreePageCount",
    (0x0001, 0x005B): "GetSysPageCount",
    (0x0001, 0x005C): "GetVMPgCount",
    (0x0001, 0x005D): "MapIntoV86",
    (0x0001, 0x005E): "PhysIntoV86",
    (0x0001, 0x005F): "TestGlobalV86Mem",
    (0x0001, 0x0060): "ModifyPageBits",
    (0x0001, 0x0061): "CopyPageTable",
    (0x0001, 0x0062): "LinMapIntoV86",
    (0x0001, 0x0063): "LinPageLock",
    (0x0001, 0x0064): "LinPageUnLock",
    (0x0001, 0x0065): "SetResetV86Pageable",
    (0x0001, 0x0066): "GetV86PageableArray",
    (0x0001, 0x0067): "PageCheckLinRange",
    (0x0001, 0x0068): "PageOutDirtyPages",
    (0x0001, 0x0069): "PageDiscardPages",

# Informational services
    (0x0001, 0x006A): "GetNulPageHandle",
    (0x0001, 0x006B): "GetFirstV86Page",
    (0x0001, 0x006C): "MapPhysToLinear",
    (0x0001, 0x006D): "GetAppFlatDSAlias",
    (0x0001, 0x006E): "SelectorMapFlat",
    (0x0001, 0x006F): "GetDemandPageInfo",
    (0x0001, 0x0070): "GetSetPageOutCount",

    # Device VM page manager
    (0x0001, 0x0071): "Hook_V86_Page",
    (0x0001, 0x0072): "Assign_Device_V86_Pages",
    (0x0001, 0x0073): "DeAssign_Device_V86_Pages",
    (0x0001, 0x0074): "Get_Device_V86_Pages_Array",
    (0x0001, 0x0075): "MMGR_SetNULPageAddr",

    # GDT/LDT management
    (0x0001, 0x0076): "Allocate_GDT_Selector",
    (0x0001, 0x0077): "Free_GDT_Selector",
    (0x0001, 0x0078): "Allocate_LDT_Selector",
    (0x0001, 0x0079): "Free_LDT_Selector",
    (0x0001, 0x007A): "BuildDescriptorDWORDs",
    (0x0001, 0x007B): "GetDescriptor",
    (0x0001, 0x007C): "SetDescriptor",
    (0x0001, 0x007D): "MMGR_Toggle_HMA",

    # Fault handling / execution state
    (0x0001, 0x007E): "Get_Fault_Hook_Addrs",
    (0x0001, 0x007F): "Hook_V86_Fault",
    (0x0001, 0x0080): "Hook_PM_Fault",
    (0x0001, 0x0081): "Hook_VMM_Fault",
    (0x0001, 0x0082): "Begin_Nest_V86_Exec",
    (0x0001, 0x0083): "Begin_Nest_Exec",
    (0x0001, 0x0084): "Exec_Int",
    (0x0001, 0x0085): "Resume_Exec",
    (0x0001, 0x0086): "End_Nest_Exec",
    (0x0001, 0x0087): "Allocate_PM_App_CB_Area",
    (0x0001, 0x0088): "Get_Cur_PM_App_CB",
    (0x0001, 0x0089): "Set_V86_Exec_Mode",
    (0x0001, 0x008A): "Set_PM_Exec_Mode",
    (0x0001, 0x008B): "Begin_Use_Locked_PM_Stack",
    (0x0001, 0x008C): "End_Use_Locked_PM_Stack",
    (0x0001, 0x008D): "Save_Client_State",
    (0x0001, 0x008E): "Restore_Client_State",
    (0x0001, 0x008F): "Exec_VxD_Int",
    (0x0001, 0x0090): "Hook_Device_Service",
    (0x0001, 0x0091): "Hook_Device_V86_API",
    (0x0001, 0x0092): "Hook_Device_PM_API",
    (0x0001, 0x0093): "System_Control",

    # I/O and software interrupt hooks
    (0x0001, 0x0094): "Simulate_IO",
    (0x0001, 0x0095): "Install_Mult_IO_Handlers",
    (0x0001, 0x0096): "Install_IO_Handler",
    (0x0001, 0x0097): "Enable_Global_Trapping",
    (0x0001, 0x0098): "Enable_Local_Trapping",
    (0x0001, 0x0099): "Disable_Global_Trapping",
    (0x0001, 0x009A): "Disable_Local_Trapping",

    # Linked List Services
    (0x0001, 0x009B): "List_Create",
    (0x0001, 0x009C): "List_Destroy",
    (0x0001, 0x009D): "List_Allocate",
    (0x0001, 0x009E): "List_Attach",
    (0x0001, 0x009F): "List_Attach_Tail",
    (0x0001, 0x00A0): "List_Insert",
    (0x0001, 0x00A1): "List_Remove",
    (0x0001, 0x00A2): "List_Deallocate",
    (0x0001, 0x00A3): "List_Get_First",
    (0x0001, 0x00A4): "List_Get_Next",
    (0x0001, 0x00A5): "List_Remove_First",

    # Initialization & Instance Data
    (0x0001, 0x00A6): "AddInstanceItem",
    (0x0001, 0x00A7): "Allocate_Device_CB_Area",
    (0x0001, 0x00A8): "Allocate_Global_V86_Data_Area",
    (0x0001, 0x00A9): "Allocate_Temp_V86_Data_Area",
    (0x0001, 0x00AA): "Free_Temp_V86_Data_Area",
    (0x0001, 0x00AB): "Get_Profile_Decimal_Int",
    (0x0001, 0x00AC): "Convert_Decimal_String",
    (0x0001, 0x00AD): "Get_Profile_Fixed_Point",
    (0x0001, 0x00AE): "Convert_Fixed_Point_String",
    (0x0001, 0x00AF): "Get_Profile_Hex_Int",
    (0x0001, 0x00B0): "Convert_Hex_String",
    (0x0001, 0x00B1): "Get_Profile_Boolean",
    (0x0001, 0x00B2): "Convert_Boolean_String",
    (0x0001, 0x00B3): "Get_Profile_String",
    (0x0001, 0x00B4): "Get_Next_Profile_String",
    (0x0001, 0x00B5): "Get_Environment_String",
    (0x0001, 0x00B6): "Get_Exec_Path",
    (0x0001, 0x00B7): "Get_Config_Directory",
    (0x0001, 0x00B8): "OpenFile",
    (0x0001, 0x00B9): "Get_PSP_Segment",
    (0x0001, 0x00BA): "GetDOSVectors",
    (0x0001, 0x00BB): "Get_Machine_Info",
    (0x0001, 0x00BC): "GetSet_HMA_Info",
    (0x0001, 0x00BD): "Set_System_Exit_Code",
    (0x0001, 0x00BE): "Fatal_Error_Handler",
    (0x0001, 0x00BF): "Fatal_Memory_Error",
    (0x0001, 0x00C0): "Update_System_Clock",

    # Debugging services
    (0x0001, 0x00C1): "Test_Debug_Installed",
    (0x0001, 0x00C2): "Out_Debug_String",
    (0x0001, 0x00C3): "Out_Debug_Chr",
    (0x0001, 0x00C4): "In_Debug_Chr",
    (0x0001, 0x00C5): "Debug_Convert_Hex_Binary",
    (0x0001, 0x00C6): "Debug_Convert_Hex_Decimal",
    (0x0001, 0x00C7): "Debug_Test_Valid_Handle",
    (0x0001, 0x00C8): "Validate_Client_Ptr",
    (0x0001, 0x00C9): "Test_Reenter",
    (0x0001, 0x00CA): "Queue_Debug_String",
    (0x0001, 0x00CB): "Log_Proc_Call",
    (0x0001, 0x00CC): "Debug_Test_Cur_VM",
    (0x0001, 0x00CD): "Get_PM_Int_Type",
    (0x0001, 0x00CE): "Set_PM_Int_Type",
    (0x0001, 0x00CF): "Get_Last_Updated_System_Time",
    (0x0001, 0x00D0): "Get_Last_Updated_VM_Exec_Time",
    (0x0001, 0x00D1): "Test_DBCS_Lead_Byte",

    # Services added in Windows 3.1
    (0x0001, 0x00D2): "AddFreePhysPage",
    (0x0001, 0x00D3): "PageResetHandlePAddr",
    (0x0001, 0x00D4): "SetLastV86Page",
    (0x0001, 0x00D5): "GetLastV86Page",
    (0x0001, 0x00D6): "MapFreePhysReg",
    (0x0001, 0x00D7): "UnmapFreePhysReg",
    (0x0001, 0x00D8): "XchgFreePhysReg",
    (0x0001, 0x00D9): "SetFreePhysRegCalBk",
    (0x0001, 0x00DA): "Get_Next_Arena",
    (0x0001, 0x00DB): "Get_Name_Of_Ugly_TSR",
    (0x0001, 0x00DC): "Get_Debug_Options",
    (0x0001, 0x00DD): "Set_Physical_HMA_Alias",
    (0x0001, 0x00DE): "GetGlblRng0V86IntBase",
    (0x0001, 0x00DF): "Add_Global_V86_Data_Area",
    (0x0001, 0x00E0): "GetSetDetailedVMError",
    (0x0001, 0x00E1): "Is_Debug_Chr",
    (0x0001, 0x00E2): "Clear_Mono_Screen",
    (0x0001, 0x00E3): "Out_Mono_Chr",
    (0x0001, 0x00E4): "Out_Mono_String",
    (0x0001, 0x00E5): "Set_Mono_Cur_Pos",
    (0x0001, 0x00E6): "Get_Mono_Cur_Pos",
    (0x0001, 0x00E7): "Get_Mono_Chr",
    (0x0001, 0x00E8): "Locate_Byte_In_ROM",
    (0x0001, 0x00E9): "Hook_Invalid_Page_Fault",
    (0x0001, 0x00EA): "Unhook_Invalid_Page_Fault",
    (0x0001, 0x00EB): "Set_Delete_On_Exit_File",
    (0x0001, 0x00EC): "Close_VM",
    (0x0001, 0x00ED): "Enable_Touch_1st_Meg",
    (0x0001, 0x00EE): "Disable_Touch_1st_Meg",
    (0x0001, 0x00EF): "Install_Exception_Handler",
    (0x0001, 0x00F0): "Remove_Exception_Handler",
    (0x0001, 0x00F1): "Get_Crit_Status_No_Block",

    # Services added in Windows 4.0 / 95
    (0x0001, 0x00F2): "GetLastUpdatedThreadExecTime",
    (0x0001, 0x00F3): "Trace_Out_Service",
    (0x0001, 0x00F4): "Debug_Out_Service",
    (0x0001, 0x00F5): "Debug_Flags_Service",
    
    (0x0001, 0x00F6): "VMMAddImportModuleName",
    (0x0001, 0x00F7): "VMM_Add_DDB",
    (0x0001, 0x00F8): "VMM_Remove_DDB",
    (0x0001, 0x00F9): "Test_VM_Ints_Enabled",
    (0x0001, 0x00FA): "BlockOnID",
    (0x0001, 0x00FB): "Schedule_Thread_Event",
    (0x0001, 0x00FC): "Cancel_Thread_Event",
    (0x0001, 0x00FD): "Set_Thread_Time_Out",
    (0x0001, 0x00FE): "Set_Async_Time_Out",
    (0x0001, 0x00FF): "AllocateThreadDataSlot",
    (0x0001, 0x0100): "FreeThreadDataSlot",
    (0x0001, 0x0101): "CreateMutex",
    (0x0001, 0x0102): "DestroyMutex",
    (0x0001, 0x0103): "GetMutexOwner",
    (0x0001, 0x0104): "Call_When_Thread_Switched",
    (0x0001, 0x0105): "VMMCreateThread",
    (0x0001, 0x0106): "GetThreadExecTime",
    (0x0001, 0x0107): "VMMTerminateThread",
    (0x0001, 0x0108): "Get_Cur_Thread_Handle",
    (0x0001, 0x0109): "Test_Cur_Thread_Handle",
    (0x0001, 0x010A): "Get_Sys_Thread_Handle",
    (0x0001, 0x010B): "Test_Sys_Thread_Handle",
    (0x0001, 0x010C): "Validate_Thread_Handle",
    (0x0001, 0x010D): "Get_Initial_Thread_Handle",
    (0x0001, 0x010E): "Test_Initial_Thread_Handle",
    (0x0001, 0x010F): "Debug_Test_Valid_Thread_Handle",
    (0x0001, 0x0110): "Debug_Test_Cur_Thread",
    (0x0001, 0x0111): "VMM_GetSystemInitState",
    (0x0001, 0x0112): "Cancel_Call_When_Thread_Switched",
    (0x0001, 0x0113): "Get_Next_Thread_Handle",
    (0x0001, 0x0114): "Adjust_Thread_Exec_Priority",
    (0x0001, 0x0115): "Deallocate_Device_CB_Area",
    (0x0001, 0x0116): "Remove_IO_Handler",
    (0x0001, 0x0117): "Remove_Mult_IO_Handlers",
    (0x0001, 0x0118): "Unhook_V86_Int_Chain",
    (0x0001, 0x0119): "Unhook_V86_Fault",
    (0x0001, 0x011A): "Unhook_PM_Fault",
    (0x0001, 0x011B): "Unhook_VMM_Fault",
    (0x0001, 0x011C): "Unhook_Device_Service",
    (0x0001, 0x011D): "PageReserve",
    (0x0001, 0x011E): "PageCommit",
    (0x0001, 0x011F): "PageDecommit",
    (0x0001, 0x0120): "PagerRegister",
    (0x0001, 0x0121): "PagerQuery",
    (0x0001, 0x0122): "PagerDeregister",
    (0x0001, 0x0123): "ContextCreate",
    (0x0001, 0x0124): "ContextDestroy",
    (0x0001, 0x0125): "PageAttach",
    (0x0001, 0x0126): "PageFlush",
    (0x0001, 0x0127): "SignalID",
    (0x0001, 0x0128): "PageCommitPhys",
    (0x0001, 0x0129): "Register_Win32_Services",
    (0x0001, 0x012A): "Cancel_Call_When_Not_Critical",
    (0x0001, 0x012B): "Cancel_Call_When_Idle",
    (0x0001, 0x012C): "Cancel_Call_When_Task_Switched",
    (0x0001, 0x012D): "Debug_Printf_Service",
    (0x0001, 0x012E): "EnterMutex",
    (0x0001, 0x012F): "LeaveMutex",
    (0x0001, 0x0130): "Simulate_VM_IO",
    (0x0001, 0x0131): "Signal_Semaphore_No_Switch",
    (0x0001, 0x0132): "ContextSwitch",
    (0x0001, 0x0133): "PageModifyPermissions",
    (0x0001, 0x0134): "PageQuery",
    (0x0001, 0x0135): "EnterMustComplete",
    (0x0001, 0x0136): "LeaveMustComplete",
    (0x0001, 0x0137): "ResumeExecMustComplete",
    (0x0001, 0x0138): "GetThreadTerminationStatus",
    (0x0001, 0x0139): "GetInstanceInfo",
    (0x0001, 0x013A): "ExecIntMustComplete",
    (0x0001, 0x013B): "ExecVxDIntMustComplete",
    (0x0001, 0x013C): "Begin_V86_Serialization",
    (0x0001, 0x013D): "Unhook_V86_Page",
    (0x0001, 0x013E): "VMM_GetVxDLocationList",
    (0x0001, 0x013F): "VMM_GetDDBList",
    (0x0001, 0x0140): "Unhook_NMI_Event",
    (0x0001, 0x0141): "Get_Instanced_V86_Int_Vector",
    (0x0001, 0x0142): "Get_Set_Real_DOS_PSP",
    (0x0001, 0x0143): "Call_Priority_Thread_Event",
    (0x0001, 0x0144): "Get_System_Time_Address",
    (0x0001, 0x0145): "Get_Crit_Status_Thread",
    (0x0001, 0x0146): "Get_DDB",
    (0x0001, 0x0147): "Directed_Sys_Control",

    # Registry Services
    (0x0001, 0x0148): "RegOpenKey",
    (0x0001, 0x0149): "RegCloseKey",
    (0x0001, 0x014A): "RegCreateKey",
    (0x0001, 0x014B): "RegDeleteKey",
    (0x0001, 0x014C): "RegEnumKey",
    (0x0001, 0x014D): "RegQueryValue",
    (0x0001, 0x014E): "RegSetValue",
    (0x0001, 0x014F): "RegDeleteValue",
    (0x0001, 0x0150): "RegEnumValue",
    (0x0001, 0x0151): "RegQueryValueEx",
    (0x0001, 0x0152): "RegSetValueEx",
    (0x0001, 0x0153): "CallRing3",
    (0x0001, 0x0154): "Exec_PM_Int",
    (0x0001, 0x0155): "RegFlushKey",
    (0x0001, 0x0156): "PageCommitContig",
    (0x0001, 0x0157): "GetCurrentContext",
    (0x0001, 0x0158): "LocalizeSprintf",
    (0x0001, 0x0159): "LocalizeStackSprintf",
    (0x0001, 0x015A): "Call_Restricted_Event",
    (0x0001, 0x015B): "Cancel_Restricted_Event",
    (0x0001, 0x015C): "Register_PEF_Provider",
    (0x0001, 0x015D): "GetPhysPageInfo",
    (0x0001, 0x015E): "RegQueryInfoKey",
    (0x0001, 0x015F): "MemArb_Reserve_Pages",

    (0x0001, 0x0160): "Time_Slice_Sys_VM_Idle",
    (0x0001, 0x0161): "Time_Slice_Sleep",
    (0x0001, 0x0162): "Boost_With_Decay",
    (0x0001, 0x0163): "Set_Inversion_Pri",
    (0x0001, 0x0164): "Reset_Inversion_Pri",
    (0x0001, 0x0165): "Release_Inversion_Pri",
    (0x0001, 0x0166): "Get_Thread_Win32_Pri",
    (0x0001, 0x0167): "Set_Thread_Win32_Pri",
    (0x0001, 0x0168): "Set_Thread_Static_Boost",
    (0x0001, 0x0169): "Set_VM_Static_Boost",
    (0x0001, 0x016A): "Release_Inversion_Pri_ID",
    (0x0001, 0x016B): "Attach_Thread_To_Group",
    (0x0001, 0x016C): "Detach_Thread_From_Group",
    (0x0001, 0x016D): "Set_Group_Static_Boost",
    (0x0001, 0x016E): "_GetRegistryPath",
    (0x0001, 0x016F): "_GetRegistryKey",

    (0x0001, 0x0170): "_CleanupNestedExec",
    (0x0001, 0x0171): "_RegRemapPreDefKey",
    (0x0001, 0x0172): "End_V86_Serialization",
    (0x0001, 0x0173): "_Assert_Range",
    (0x0001, 0x0174): "_Sprintf",
    (0x0001, 0x0175): "_PageChangePager",
    (0x0001, 0x0176): "_RegCreateDynKey",
    (0x0001, 0x0177): "RegQMulti",
    (0x0001, 0x0178): "Boost_Thread_With_VM",
    (0x0001, 0x0179): "Get_Boot_Flags",
    (0x0001, 0x017A): "Set_Boot_Flags",
    (0x0001, 0x017B): "_lstrcpyn",
    (0x0001, 0x017C): "_lstrlen",
    (0x0001, 0x017D): "_lmemcpy",
    (0x0001, 0x017E): "_GetVxDName",
    (0x0001, 0x017F): "Force_Mutexes_Free",
    
    (0x0001, 0x0180): "Restore_Forced_Mutexes",
    (0x0001, 0x0181): "_AddReclaimableItem",
    (0x0001, 0x0182): "_SetReclaimableItem",
    (0x0001, 0x0183): "_EnumReclaimableItem",
    (0x0001, 0x0184): "Time_Slice_Wake_Sys_VM",
    (0x0001, 0x0185): "VMM_Replace_Global_Environment",
    (0x0001, 0x0186): "Begin_Non_Serial_Nest_V86_Exec",
    (0x0001, 0x0187): "Get_Nest_Exec_Status",
    (0x0001, 0x0188): "Open_Boot_Log",
    (0x0001, 0x0189): "Write_Boot_Log",
    (0x0001, 0x018A): "Close_Boot_Log",
    (0x0001, 0x018B): "EnableDisable_Boot_Log",
    (0x0001, 0x018C): "_Call_On_My_Stack",
    (0x0001, 0x018D): "Get_Inst_V86_Int_Vec_Base",
    (0x0001, 0x018E): "_lstrcmpi",
    (0x0001, 0x018F): "_strupr",
    
    (0x0001, 0x0190): "Log_Fault_Call_Out",
    (0x0001, 0x0191): "_AtEventTime",
    
    # Added in Windows 95 OSR1 (Win4.03)   
    (0x0001, 0x0192): "_Call_On_My_Not_Flat_Stack",
    (0x0001, 0x0193): "_LinRegionLock",
    (0x0001, 0x0194): "_LinRegionUnLock",
    (0x0001, 0x0195): "_AttemptingSomethingDangerous", #0w0
    (0x0001, 0x0196): "_Vsprintf",
    (0x0001, 0x0197): "_Vsprintfw",
    (0x0001, 0x0198): "Load_FS_Service",
    (0x0001, 0x0199): "Assert_FS_Service",
    (0x0001, 0x019a): "ObsoleteRtlUnwind", #Stdcall, 4
    (0x0001, 0x019b): "ObsoleteRtlRaiseException", #Stdcall, 1
    (0x0001, 0x019c): "ObsoleteRtlRaiseStatus", #Stdcall, 1
    (0x0001, 0x019d): "ObsoleteKeGetCurrentIrql", #Stdcall, 1
    (0x0001, 0x019e): "ObsoleteKfRaiseIrql", #Fastcall,1
    (0x0001, 0x019f): "ObsoleteKfLowerIrql", #Fastcall,1
    
    (0x0001, 0x01a0): "_Begin_Preemptable_Code",
    (0x0001, 0x01a1): "_End_Preemptable_Code)",
    (0x0001, 0x01a2): "Set_Preemptable_Count", #Fastcall,1
    (0x0001, 0x01a3): "ObsoleteKeInitializeDpc", #Stdcall, 3
    (0x0001, 0x01a4): "ObsoleteKeInsertQueueDpc", #Stdcall, 3
    (0x0001, 0x01a5): "ObsoleteKeRemoveQueueDpc", #Stdcall, 1
    (0x0001, 0x01a6): "HeapAllocateEx", #Stdcall, 4
    (0x0001, 0x01a7): "HeapReAllocateEx", #Stdcall, 5
    (0x0001, 0x01a8): "HeapGetSizeEx", #Stdcall, 2
    (0x0001, 0x01a9): "HeapFreeEx", #Stdcall, 2
    (0x0001, 0x01aa): "_Get_CPUID_Flags",
    (0x0001, 0x01ab): "KeCheckDivideByZeroTrap", #Stdcall, 1

    # Added in Windows 98 (Win4.1)
    (0x0001, 0x01ac): "_RegisterGARTHandler",
    (0x0001, 0x01ad): "_GARTReserve",
    (0x0001, 0x01ae): "_GARTCommit",
    (0x0001, 0x01af): "_GARTUnCommit",
    
    (0x0001, 0x01b0): "_GARTFree",
    (0x0001, 0x01b1): "_GARTMemAttributes",
    (0x0001, 0x01b2): "KfRaiseIrqlToDpcLevel", #Stdcall, 0
    (0x0001, 0x01b3): "VMMCreateThreadEx",
    (0x0001, 0x01b4): "_FlushCaches",
    (0x0001, 0x01b5): "Set_Thread_Win32_Pri_NoYield",
    (0x0001, 0x01b6): "_FlushMappedCacheBlock",
    (0x0001, 0x01b7): "_ReleaseMappedCacheBlock",
    (0x0001, 0x01b8): "Run_Preemptable_Events",
    (0x0001, 0x01b9): "_MMPreSystemExit",
    (0x0001, 0x01ba): "_MMPageFileShutDown",
    (0x0001, 0x01bb): "_Set_Global_Time_Out_Ex",
    (0x0001, 0x01bc): "Query_Thread_Priority",
    #whew.

    #
    # DEBUG (0002h)
    #

    (0x0002, 0x0000): "Get_Version",
    (0x0002, 0x0001): "DEBUG_Fault",
    (0x0002, 0x0002): "DEBUG_CheckFault",
    (0x0002, 0x0003): "_DEBUG_LoadSyms",

    #
    # VPICD (0003h)
    #

    (0x0003, 0x0000): "Get_Version",
    (0x0003, 0x0001): "Virtualize IRQ",
    (0x0003, 0x0002): "Set Interrupt Request",
    (0x0003, 0x0003): "Clear Interrupt Request",
    (0x0003, 0x0004): "Phys_EOI",
    (0x0003, 0x0005): "Get_Complete_Status",
    (0x0003, 0x0006): "Get_Status",
    (0x0003, 0x0007): "Test_Phys_Request",
    (0x0003, 0x0008): "Physically_Mask",
    (0x0003, 0x0009): "Physically_Unmask",
    (0x0003, 0x000A): "Set_Auto_Masking",
    (0x0003, 0x000B): "Get_IRQ_Complete_Status",
    (0x0003, 0x000C): "Convert_Handle_To_IRQ",
    (0x0003, 0x000D): "Convert_IRQ_To_Int",
    (0x0003, 0x000E): "Convert_Int_To_IRQ",
    (0x0003, 0x000F): "Call_When_Hw_Int",
    
    (0x0003, 0x0010): "Force_Default_Owner",
    (0x0003, 0x0011): "Force_Default_Behavior",
    (0x0003, 0x0012): "Auto_Mask_At_Inst_Swap",
    (0x0003, 0x0013): "Begin_Inst_Page_Swap",
    (0x0003, 0x0014): "End_Inst_Page_Swap",
    (0x0003, 0x0015): "Virtual_EOI",
    (0x0003, 0x0016): "Get_Virtualization_Count",
    (0x0003, 0x0017): "Post_Sys_Critical_Init",
    (0x0003, 0x0018): "VM_SlavePIC_Mask_Change",
    (0x0003, 0x0019): "Clear_IR_Bits",
    (0x0003, 0x001A): "Get_Level_Mask",
    (0x0003, 0x001B): "Set_Level_Mask",
    (0x0003, 0x001C): "Set_Irql_Mask",
    (0x0003, 0x001D): "Set_Channel_Irql",
    (0x0003, 0x001E): "Prepare_For_Shutdown",
    (0x0003, 0x001F): "Register_Trigger_Handler",



    #
    # VDMAD (0004h)
    #
    
    (0x0004, 0x0000): "Get_Version",
    (0x0004, 0x0001): "virtualize channel",
    (0x0004, 0x0002): "get region information",
    (0x0004, 0x0003): "set region information",
    (0x0004, 0x0004): "get virtual state",
    (0x0004, 0x0005): "set virtual state",
    (0x0004, 0x0006): "set physical state",
    (0x0004, 0x0007): "mask channel",
    (0x0004, 0x0008): "unmask channel",
    (0x0004, 0x0009): "lock DMA region",
    (0x0004, 0x000a): "unlock DMA region",
    (0x0004, 0x000b): "scatter lock",
    (0x0004, 0x000c): "scatter unlock",
    (0x0004, 0x000d): "reserve buffer space",
    (0x0004, 0x000e): "request buffer",
    (0x0004, 0x000f): "release buffer",
    
    (0x0004, 0x0010): "copy to buffer",
    (0x0004, 0x0011): "copy from buffer",
    (0x0004, 0x0012): "default handler",
    (0x0004, 0x0013): "disable translation",
    (0x0004, 0x0014): "enable translation",
    (0x0004, 0x0015): "get EISA address mode",
    (0x0004, 0x0016): "set EISA address mode",
    (0x0004, 0x0017): "unlock DMA region (ND)",
    (0x0004, 0x0018): "Phys_Mask_Channel",
    (0x0004, 0x0019): "Phys_Unmask_Channel",
    (0x0004, 0x001A): "Unvirtualize_Channel",
    (0x0004, 0x001B): "Set_IO_Address",
    (0x0004, 0x001C): "Get_Phys_Count",
    (0x0004, 0x001D): "Get_Phys_Status",
    (0x0004, 0x001E): "Get_Max_Phys_Page",
    (0x0004, 0x001F): "Set_Channel_Callbacks",
    
    (0x0004, 0x0020): "Get_Virt_Count",
    (0x0004, 0x0021): "Set_Virt_Count",

    #
    # VTD (0005h)
    #

    (0x0005, 0x0000): "Get_Version",
    (0x0005, 0x0001): "update system clock",
    (0x0005, 0x0002): "get interrupt period",
    (0x0005, 0x0003): "begin minimum interrupt period",
    (0x0005, 0x0004): "end minimum interrupt period",
    (0x0005, 0x0005): "disable trapping",
    (0x0005, 0x0006): "enable trapping",
    (0x0005, 0x0007): "get real time",
    (0x0005, 0x0008): "Get_Date_And_Time",
    (0x0005, 0x0009): "Adjust_VM_Count",
    (0x0005, 0x000A): "Delay",


    # ...


}

VXD_NAMES = {
    0x0000: "UNDEFINED",
    0x0001: "VMM",
    0x0002: "DEBUG",
    0x0003: "VPICD",
    0x0004: "VDMAD",
    0x0005: "VTD",
    0x0006: "V86MMGR",
    0x0007: "PAGESWAP",
    0x0008: "PARITY",
    0x0009: "REBOOT",
    0x000A: "VDD",
    0x000B: "VSD",
    0x000C: "VMD", #VMOUSE on Win9x
    0x000D: "VKD",
    0x000E: "VCD",
    0x000F: "VPD",
    0x0010: "BLOCKDEV",
    0x0011: "VMCPD",
    0x0012: "EBIOS",
    0x0013: "BIOSXLAT",
    0x0014: "VNETBIOS",
    0x0015: "DOSMGR",
    0x0016: "WINLOAD",
    0x0017: "SHELL",
    0x0018: "VMPOLL",
    0x0019: "VPROD",
    0x001A: "DOSNET",
    0x001B: "VFD",
    0x001C: "VDD2",
    0x001D: "WINDEBUG",
    0x001E: "TSRLOAD",
    0x001F: "BIOSHOOK",
    0x0020: "INT13",
    0x0021: "PAGEFILE",
    0x0022: "SCSI",
    0x0023: "MCA_POS",
    0x0024: "SCSIFD",
    0x0025: "VPEND",
    0x0026: "APM",
    0x0027: "VXDLDR",
    0x0028: "NDIS",
    0x0029: "BIOS_EXT",
    0x002A: "VWIN32",
    0x002B: "VCOMM",
    0x002C: "SPOOLER",
    0x002D: "WIN32S",
    0x002E: "DEBUGCMD",
    0x0033: "CONFIGMG",
    0x0034: "DWCFGMG",
    0x0035: "SCSIPORT",
    0x0036: "VFBACKUP",
    0x0037: "ENABLE",
    0x0038: "VCOND",
    0x003C: "ISAPNP",
    0x003D: "BIOS",
    0x0040: "IFSMGR",
    0x0041: "VCDFSD",
    0x0042: "MRCI2",
    0x0043: "PCI",
    0x0044: "PELOADER",
    0x0045: "EISA",
    0x0046: "DRAGCLI",
    0x0047: "DRAGSRV",
    0x0048: "PERF",
    0x0049: "AWREDIR",
    0x004A: "DDS",
    0x004B: "NTKERN",
    0x004C: "ACPI",
    0x004D: "UDF",
    0x004E: "SMCLIB",
    0x0060: "ETEN",
    0x0061: "CHBIOS",
    0x0062: "VMSGD",
    0x0063: "VPPID",
    0x0064: "VIME",
    0x0065: "VHBIOSD",
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

        svc_id = read_u16(struct_addr)
        vxd_id = read_u16(struct_addr.add(2))

    except:
        continue
    
    #
    # Check for inline payload bytes after the 4-byte struct
    #

    #High bit set on service ID = callable from ring 3
    base_svc_id = svc_id & 0x7FFF
    extra_len = 0
    extra_type = None  # 'WORD' or 'STRING'

    if vxd_id == 0x0001:  # VMM
        if base_svc_id == 0x00F5:  # _Debug_Flags_Service
            extra_len = 2
            extra_type = "WORD"
        elif base_svc_id in (0x00F3, 0x00F4, 0x012D):  # Trace_Out, Debug_Out, Debug_Printf
                str_addr = struct_addr.add(4)
                str_len = 0
                b = -1
                
                # 1. Scan for string null terminator
                while b != 0 and str_len < 256:
                    try:
                        b = getByte(str_addr.add(str_len)) & 0xFF
                        str_len += 1
                    except:
                        break
                
                # 2. Absorb trailing align 4 padding bytes (00)
                curr_offset = str_addr.add(str_len).getOffset()
                rem = curr_offset % 4
                if rem != 0:
                    pad_needed = 4 - rem
                    pad_bytes = 0
                    while pad_bytes < pad_needed:
                        try:
                            if getByte(str_addr.add(str_len + pad_bytes)) == 0:
                                pad_bytes += 1
                            else:
                                break
                        except:
                            break
                    str_len += pad_bytes

                extra_len = str_len
                extra_type = "STRING"

    total_payload_len = 4 + extra_len
    next_addr = struct_addr.add(total_payload_len)

    #
    # 1. Clear payload
    #
    
    clear_end = next_addr.add(0)
    clearListing(struct_addr, clear_end)

    #
    # 2. Delete stale "Error" bookmarks across the cleared region
    #
    
    bm = currentProgram.getBookmarkManager()
    curr_addr = int_addr
    while curr_addr.compareTo(clear_end) <= 0:
        bookmarks = bm.getBookmarks(curr_addr)
        if bookmarks is not None:
            for b in list(bookmarks):
                if b.getTypeString() == "Error":
                    bm.removeBookmark(b)
        curr_addr = curr_addr.add(1)

    #
    # 3. Apply 4-byte VxDCall structure
    #
    
    try:
        createData(struct_addr, vxdcall_struct)
    except Exception as e:
        print("Failed to apply structure at %s: %s" % (struct_addr, str(e)))
        continue

    #
    # 4. Apply data type to inline payload if present
    #
    
    extra_addr = struct_addr.add(4)
    if extra_type == "WORD":
        try:
            createWord(extra_addr)
        except Exception as e:
            print("Failed to create WORD at %s: %s" % (extra_addr, str(e)))
    elif extra_type == "STRING" and extra_len > 0:
        try:
            createAsciiString(extra_addr, extra_len)
        except Exception as e:
            print("Failed to create String at %s: %s" % (extra_addr, str(e)))

    #
    # 5. Disassemble cleanly from next_addr
    #
    
    disassemble(next_addr)
    
    #
    # Resolve names
    #


    is_win32_export = bool(svc_id & 0x8000)
    

    vxd_name = VXD_NAMES.get(
        vxd_id,
        "VXD_%04X" % vxd_id
    )

    svc_name = SERVICES.get(
        (vxd_id, base_svc_id),
        "Service_%04X" % base_svc_id
    )
    
    #high bit of service name set = JMP rather than call (?)
    
    suffix = "_JMP" if is_win32_export else ""
    full_name = "%s.%s%s" % (
        vxd_name,
        svc_name,
        suffix
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
        "VxDCall_%s_%s%s" % (
            vxd_name,
            svc_name,
            suffix
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
