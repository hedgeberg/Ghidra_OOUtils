//
//@author 
//@category 
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ooutils.object.OOUtilsClass;

public class SpawnNewClassFromVtable extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String className = askString("Class Name", "What should the new class be named?");
		int vtableLen = askInt("Vtable Length", "How many entries in the new class?");
		
		OOUtilsClass newClass = OOUtilsClass.newAutoClassFromVtable(currentAddress,
				vtableLen, className, currentProgram);
		println(String.format("New Obj: {}", newClass));
	}
}
