//Increase the length of the OOUtils managed vtable at the current cursor location by 1 slot
//@author hedgeberg
//@category OOUtils
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.plugins.ooutils.object.OOUtilsClass;
import ghidra.plugins.ooutils.object.ns.OOUtilsPath;
import ghidra.program.model.listing.VariableSizeException;

public class GrowVtableByOne extends GhidraScript {

	@Override
	protected void run() throws Exception {
		OOUtilsPath path = OOUtilsPath.fromVtableAddress(currentAddress, currentProgram);
		OOUtilsClass currentClass = new OOUtilsClass(path, currentProgram);
		Boolean clearAndRetry = false;
		try {
			currentClass.growVtableSingle();
		} catch (VariableSizeException e) {
			clearAndRetry = askYesNo("OOUtils Grow VTable Error", 
					String.format("Can't grow the VTable for class %s @ %s because there is defined data in the way. Clear data?", 
					currentClass.getName(), currentClass.getVtableStartAddress()));
		}
		if(clearAndRetry) {
			currentClass.clearForNewSlot();
			currentClass.growVtableSingle();
		}
	}
}
