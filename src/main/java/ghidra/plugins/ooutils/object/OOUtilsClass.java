package ghidra.plugins.ooutils.object;

import ghidra.plugins.ooutils.object.vtable.OOUtilsVtable;
import ghidra.plugins.ooutils.utils.Helpers;

import java.util.List;

import ghidra.plugins.ooutils.object.ns.OOUtilsPath;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableSizeException;
import ghidra.program.database.symbol.SymbolManager;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.GhidraClass;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class OOUtilsClass {
	
	SymbolTable st;
	Listing listing;
	DataTypeManager dtm;
	GhidraClass classNs;
	Structure classStruct;
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
		DataType toCast = dtm.getDataType(path.getContainingCategoryPath(), path.getClassName());
		assert(toCast instanceof Structure);
		this.classStruct = (Structure) toCast;
	}
	
	public void tryClaimVtableSlots() {
		vt.claimSlots();
	}
	
	public String getName() {
		return path.getClassNsString();
	}
	
	public Address getVtableStartAddress() {
		return vt.getVtableStartAddress();
	}
	
	public void clearForNewSlot() {
		vt.clearForNewSlot();
	}
	
	public OOUtilsVtable getOOUtilsVtable() {
		return vt;
	}
	
	public OOUtilsPath getOOUtilsPath() {
		return path;
	}
	
	public void updateClassVtableDefinitions() {
		vt.updateVtableOwnedImplDefinitions();
	}
	
	public void growVtableSingle() throws VariableSizeException {
		//Add a single slot to the vtable
		vt.growVtableSingle();
	}
	
	public void shrinkVtableSingle(TaskMonitor mon) throws VariableSizeException {
		//Remove a single slot from the vtable
		vt.shrinkVtableSingle(mon);
	}
	
	public Boolean changeClassName(String newName, TaskMonitor mon) throws InvalidInputException, InvalidNameException {
		//Change the name (note: not the ns/path) of a class
		//Step 1: verify we can actually make the change. Requires that there isn't already a class with this same name in this same namespace
		//1a: check for a conflicting class symbol
		if(st.getClassSymbol(newName, path.getParentNamespace()) != null) {
			return false;
		}
		//1b: check for a conflicting namespace
		if(st.getNamespace(newName, path.getParentNamespace()) != null) {
			return false;
		}
		//1c: check for a conflicting symbol
		if(st.getSymbols(newName, path.getParentNamespace()).size() != 0) {
			return false;
		}
		//Step 1 continues in vt.ChangeClassName
		if(!vt.changeClassName(newName, mon)) {
			return false;
		}
		//2b: rename the class struct
		try {
			classStruct.setName(newName);
		} catch (DuplicateNameException e) {
			//this *should* be impossible to hit thanks to our checks
			assert(false);
		}
		//Step 3: rename the class in the symbol tree
		Symbol classSym = st.getClassSymbol(classNs.getName(), path.getParentNamespace());
		try {
			classSym.setName(newName, SourceType.USER_DEFINED);
		} catch (DuplicateNameException e) {
			//this *should* be impossible to hit thanks to our checks
			assert(false);
		}
		path.changeClassName(newName, mon);
		return true;
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
	
	public static OOUtilsClass fromVtableAddress(Address vtableAddress, Program pgm) {
		OOUtilsPath path = OOUtilsPath.fromVtableAddress(vtableAddress, pgm);
		OOUtilsClass newClass = new OOUtilsClass(path, pgm);
		return newClass;
	}
}
