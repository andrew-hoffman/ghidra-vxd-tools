# ghidra-vxd-tools
Ghidra Jython scripts for disassembling Windows VxD device drivers

Last tested on Ghidra 12.0.1, latest version with the LE loader plugin 
https://github.com/yetmorecode/ghidra-lx-loader

may have problems on 12.1 where PyGhidra is preferred scripting

Scripts go in $USER_HOME\ghidra_scripts (you may have to create a new script in the script manager before this folder will be created)

Will appear in category "Windows9x" in the Script Manager

You may need to "Refresh Script List" if you update the script while Ghidra is running.

Other important tools for Windows driver RE:
https://github.com/ExplodingBottle/sym2map
