package ghidra.plugins.ooutils.object;

import ghidra.plugins.ooutils.object.vtable.OOUtilsVtable;
import ghidra.plugins.ooutils.utils.Helpers;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.database.symbol.SymbolManager;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.GhidraClass;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class OOUtilsClass {
	
	SymbolManager sm;
	Listing listing;
	DataTypeManager dtm;
	GhidraClass classNs;
	Program pgm;
	
	
	public OOUtilsClass(Namespace ns, String className, Program pgm){
		this.dtm = pgm.getDataTypeManager();
		this.listing = pgm.getListing();
		this.sm = (SymbolManager) pgm.getSymbolTable();
		//TODO: need a way to verify this is actually an OOUtilsClass and not just a manually created class
		//TODO: split className into namespace & name
		this.classNs = (GhidraClass) sm.getNamespace(className, ns);
	}
	
	public static OOUtilsClass newAutoClassFromVtable(Address vtableStart, int numVtableMembers, Namespace ns, String className, 
			Program pgm) throws DuplicateNameException, InvalidInputException {
		CategoryPath catPath;
		if(ns != null) {
			catPath = new CategoryPath("/OOUtils_Managed" + Helpers.nsPathToSlashPath(ns.getName()));

		} else {
			catPath = new CategoryPath("/OOUtils_Managed");
		}
		//TODO: a class for storing the class name & paths? feels useful here considering gross path logic.
		OOUtilsVtable newVtable = OOUtilsVtable.newAutoVtable(vtableStart, numVtableMembers, catPath, 
				className, pgm);
		if(newVtable == null) {
			Msg.error(OOUtilsClass.class, "newAutoClass failed to get a valid vtable");
			return null;
		}
		//TODO: Add a new class struct
		DataTypeManager dtm = pgm.getDataTypeManager();
		SymbolManager sm = (SymbolManager) pgm.getSymbolTable();
		GhidraClass newGhidraClass = sm.createClass(ns, className, SourceType.USER_DEFINED);
		sm.createLabel(newVtable.vtableStartAddress, newVtable.vtableTypeName, newGhidraClass, SourceType.USER_DEFINED);
		DataType vtableType = newVtable.getVtableDataType();
		StructureDataType newClassStruct = new StructureDataType(catPath, className, Helpers.getArchFuncPtrSize(pgm));
		newClassStruct.replaceAtOffset(0, dtm.getPointer(vtableType), vtableType.getLength() * 2, "_vtbl", "");
		dtm.addDataType(newClassStruct, DataTypeConflictHandler.DEFAULT_HANDLER);
		OOUtilsClass newClass = new OOUtilsClass(ns, className, pgm);
		return newClass;
	}
}
