package ghidra.plugins.ooutils.object;

import ghidra.plugins.ooutils.object.vtable.OOUtilsVtable;
import ghidra.plugins.ooutils.utils.Helpers;

import java.util.List;

import ghidra.plugins.ooutils.object.ns.OOUtilsPath;

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
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.listing.GhidraClass;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class OOUtilsClass {
	
	SymbolTable st;
	Listing listing;
	DataTypeManager dtm;
	GhidraClass classNs;
	Program pgm;
	OOUtilsPath path;
	OOUtilsVtable vt;
	
	//public OOUtilsClass(Namespace ns, String className, Program pgm){

	
	public OOUtilsClass(OOUtilsPath path, Program pgm){
		this.dtm = pgm.getDataTypeManager();
		this.listing = pgm.getListing();
		this.st = pgm.getSymbolTable();
		this.path = path;
		//TODO: need a way to verify this is actually an OOUtilsClass and not just a manually created class
		this.classNs = path.getClassNamespace();
		List<Symbol> vftableSymbols = st.getSymbols("vftable", classNs);
		//TODO: actually handle multiple vtables for a single class
		assert(vftableSymbols.size() == 1);
		Symbol vtableSymbol = vftableSymbols.get(0);
		this.vt = new OOUtilsVtable(vtableSymbol.getAddress(), path, pgm);
	}
	
	public void tryClaimVtableSlots() {
		vt.claimSlots();
	}
	
	public String getName() {
		return path.getClassNsString();
	}
	
	public void updateClassVtableDefinitions() {
		vt.updateVtableOwnedImplDefinitions();
	}
	
	public static OOUtilsClass newAutoClassFromVtable(Address vtableStart, int numVtableMembers, OOUtilsPath path,
			Program pgm) throws DuplicateNameException, InvalidInputException {
		CategoryPath catPath = path.getContainingCategoryPath();
		Namespace ns = path.getParentNamespace();
		String className = path.getClassName();
		//TODO: a class for storing the class name & paths? feels useful here considering gross path logic.
		OOUtilsVtable newVtable = OOUtilsVtable.newAutoVtable(vtableStart, numVtableMembers, path, pgm);
		if(newVtable == null) {
			Msg.error(OOUtilsClass.class, "newAutoClass failed to get a valid vtable");
			return null;
		}
		//TODO: Add a new class struct
		DataTypeManager dtm = pgm.getDataTypeManager();
		SymbolManager sm = (SymbolManager) pgm.getSymbolTable();
		GhidraClass newGhidraClass = sm.createClass(ns, className, SourceType.USER_DEFINED);
		sm.createLabel(newVtable.vtableStartAddress, newVtable.vtableTypeName, newGhidraClass,
				SourceType.USER_DEFINED).setPrimary();
		DataType vtableType = newVtable.getVtableDataType();
		StructureDataType newClassStruct = new StructureDataType(catPath, className, Helpers.getArchFuncPtrSize(pgm)*2);
		newClassStruct.replaceAtOffset(0, dtm.getPointer(vtableType), dtm.getPointer(vtableType).getLength(), "_vtbl", "");
		dtm.addDataType(newClassStruct, DataTypeConflictHandler.DEFAULT_HANDLER);
		OOUtilsClass newClass = new OOUtilsClass(path, pgm);
		return newClass;
	}
}
