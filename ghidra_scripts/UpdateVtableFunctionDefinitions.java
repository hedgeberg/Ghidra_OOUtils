//
//@author hedgeberg
//@category OOUtils
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;

import ghidra.plugins.ooutils.object.ns.OOUtilsPath;
import ghidra.plugins.ooutils.object.OOUtilsClass;

public class UpdateVtableFunctionDefinitions extends GhidraScript {

	@Override
	protected void run() throws Exception {
		OOUtilsPath path = OOUtilsPath.fromVtableAddress(currentAddress, currentProgram);
		OOUtilsClass currentClass = new OOUtilsClass(path, currentProgram);
		currentClass.updateClassVtableDefinitions();
		println(String.format("OOUtils updated function definitions for: %s", currentClass.getName()));
	}
}
