//Changes the name (not the namespace!) of an OOUtils-managed class
//@author hedgeberg
//@category OOUtils
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.plugins.ooutils.object.OOUtilsClass;

public class RenameOOUtilsClass extends GhidraScript {

	@Override
	protected void run() throws Exception {
		OOUtilsClass workingClass = OOUtilsClass.fromVtableAddress(currentAddress, currentProgram);
		String newName = askString("New class name", "Please input the new name for the class:");
		Boolean result = workingClass.changeClassName(newName, monitor);
		if(!result) {
			popup("Couldn't change the class name because something in the DTM or ST already has that name.");
		}
	}
}
