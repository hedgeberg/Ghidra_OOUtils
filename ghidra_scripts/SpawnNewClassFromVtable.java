//
//@author 
//@category 
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.plugins.ooutils.object.OOUtilsClass;
//import ghidra.plugins.ooutils.utils.Helpers;
//import ghidra.program.model.symbol.Namespace;
import ghidra.plugins.ooutils.object.ns.OOUtilsPath;

public class SpawnNewClassFromVtable extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String classNameCombined = askString("Class Name", "What should the new class be named?");
		int vtableLen = askInt("Vtable Length", "How many entries in the new class?");
		//String[] splitOut = Helpers.splitOutClassFromNamespace(classNameCombined);
		//Namespace ns = Helpers.resolveStringToNamespace(splitOut[1], currentProgram);
		//String className = splitOut[0];
		OOUtilsPath newObjPath = new OOUtilsPath(classNameCombined, currentProgram);
		newObjPath.ensureParentNamespacePath();
		OOUtilsClass newClass = OOUtilsClass.newAutoClassFromVtable(currentAddress,
				vtableLen, newObjPath, currentProgram);
		println(String.format("New Obj: %s", newClass));
	}
}
