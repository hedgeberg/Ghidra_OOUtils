//Same as SpawnNewClassFromVtable.java, but generates a vtable with exactly 1 slot, which you can then expand as needed using AddVtableSlot.java
//@author hedgeberg
//@category OOUtils
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.plugins.ooutils.object.OOUtilsClass;
import ghidra.plugins.ooutils.object.ns.OOUtilsPath;

public class InstantSpawnClass extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String classNameCombined = askString("Class Name", "What should the new class be named?");
		OOUtilsPath newObjPath = new OOUtilsPath(classNameCombined, currentProgram);
		newObjPath.ensureParentNamespacePath();
		OOUtilsClass newClass = OOUtilsClass.newAutoClassFromVtable(currentAddress,
				1, newObjPath, currentProgram);
		println(String.format("New Obj: %s, named %s", newClass, newClass.getName()));
		newClass.tryClaimVtableSlots();
	}
}
