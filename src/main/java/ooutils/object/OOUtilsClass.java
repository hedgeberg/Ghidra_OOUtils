package ooutils.object;

import ooutils.object.vtable.OOUtilsVtable;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
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
	
	
	public OOUtilsClass(String className, Program pgm){
		this.dtm = pgm.getDataTypeManager();
		this.listing = pgm.getListing();
		this.sm = (SymbolManager) pgm.getSymbolTable();
		//TODO: need a way to verify this is actually an OOUtilsClass and not just a manually created class
		//TODO: split className into namespace & name
		this.classNs = (GhidraClass) sm.getNamespace(className, null);
		
	}
	
	public static OOUtilsClass newAutoClassFromVtable(Address vtableStart, int numVtableMembers, String className, 
			Program pgm) throws DuplicateNameException, InvalidInputException {
		//TODO: split class path up or remove the need in newVtable
		OOUtilsVtable newVtable = OOUtilsVtable.newAutoVtable(vtableStart, numVtableMembers, "", 
				className, pgm);
		if(newVtable == null) {
			Msg.error(OOUtilsClass.class, "newAutoClass failed to get a valid vtable");
			return null;
		}
		Namespace nm = null;
		SymbolManager sm = (SymbolManager) pgm.getSymbolTable();
		GhidraClass newGhidraClass = sm.createClass(nm, className, SourceType.USER_DEFINED);
		sm.createLabel(newVtable.vtableStartAddress, newVtable.vtableTypeName, newGhidraClass, SourceType.USER_DEFINED);
		OOUtilsClass newClass = new OOUtilsClass(className, pgm);
		return newClass;
	}
}
