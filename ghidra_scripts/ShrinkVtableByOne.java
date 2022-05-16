//Reduce the length of the OOUtils managed vtable at the current cursor location by 1 slot
//@author hedgeberg
//@category OOUtils
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.plugins.ooutils.object.OOUtilsClass;
import ghidra.plugins.ooutils.object.ns.OOUtilsPath;
import ghidra.program.model.listing.VariableSizeException;

public class ShrinkVtableByOne extends GhidraScript {

	@Override
	protected void run() throws Exception {
		OOUtilsPath path = OOUtilsPath.fromVtableAddress(currentAddress, currentProgram);
		OOUtilsClass currentClass = new OOUtilsClass(path, currentProgram);
		try {
			currentClass.shrinkVtableSingle(monitor);
		} catch (VariableSizeException e) {
			popup(String.format("Can't shrink the VTable for class %s @ %s because it already has a size of 1!", 
					currentClass.getName(), currentClass.getVtableStartAddress()));
		}
	}
}
