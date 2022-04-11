package ooutils.object.vtable;

import java.lang.String;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.Msg;

public class OOUtilsVtable {
	//static int PTR_WIDTH = 4; //TODO: fetch this from lang spec
	
	public Address vtableStartAddress;
	public String vtableTypeName;
	
	int numPtrs;
	int ptrWidth;
	String classPath;
	CategoryPath catPath;
	DataType vtableDataType;
	Structure vtableStruct;
	DataTypeManager dtm;
	Listing listing;
	ReferenceManager rm;
	Program pgm;
	
	
	public OOUtilsVtable(Address start, int numPtrs, String classPath, String vtableTypeName, Program pgm){
		//Assumes that a vtable that has been created by OOUtils already exists for this type. 
		//If it doesn't, you should call newAutoVtable instead. 
		vtableStartAddress = start;
		this.dtm = pgm.getDataTypeManager();
		this.vtableTypeName = vtableTypeName;
		this.classPath = classPath;
		this.catPath = new CategoryPath(classPath);
		this.listing = pgm.getListing();
		this.rm = pgm.getReferenceManager();
		this.ptrWidth = dtm.getPointer(new FunctionDefinitionDataType("funcname")).getLength();
		this.numPtrs = numPtrs;
		
		this.vtableDataType = dtm.getDataType(catPath, vtableTypeName);
		//this.vtableDataType = (StructureDataType) listing.getDataAt(start).getDataType();
		//this.vtableStruct = (Structure) listing.getDataAt(start);
	}
	
	public Boolean applyAtAddress() {
		try {
			listing.createData(vtableStartAddress, vtableDataType);
		} catch (CodeUnitInsertionException | DataTypeConflictException e) {
			Msg.error(this, "Could not spawn new Vtable at the desired location");
			return false;
		}
		return true;
	}
	
	public void initialPopulateVtableStruct()  {
		StructureDataType newDataType = (StructureDataType) vtableDataType.clone(dtm);
		for(int slot = 0; slot < numPtrs; slot++) {
			int offset = slot * ptrWidth;
			String slotName = String.format("slot%d", slot);
			FunctionDefinitionDataType slotFuncDef = new FunctionDefinitionDataType(catPath, slotName);
			dtm.addDataType(slotFuncDef, DataTypeConflictHandler.DEFAULT_HANDLER);
			DataType slotDataType = dtm.getPointer(slotFuncDef);
			newDataType.replaceAtOffset(offset, slotDataType, slotDataType.getLength(), slotName, "");
		}
		vtableDataType.replaceWith(newDataType);
	}
	
	public static OOUtilsVtable newAutoVtable(Address startAddr, int numPtrs, String classPath,
			String className, Program pgm) {
		//create a new Ghidra data type for this vtable and add it to dtm:
		DataTypeManager dtm = pgm.getDataTypeManager();
		int PTR_WIDTH = dtm.getPointer(new FunctionDefinitionDataType("funcname")).getLength();
		CategoryPath dtCategoryPath = new CategoryPath("/OOUtils_Managed" + classPath + "/" + className);
		int vtLength = PTR_WIDTH * numPtrs;
		//TODO: increment vftable numbers?
		String vtableTypeName = "vftable";
		StructureDataType vtableStruct = new StructureDataType(dtCategoryPath, vtableTypeName, vtLength, dtm);
		dtm.addDataType(vtableStruct, DataTypeConflictHandler.DEFAULT_HANDLER);
		
		//Once that's been added, we're safe to actually construct our class
		OOUtilsVtable newTable = new OOUtilsVtable(startAddr, numPtrs, "/OOUtils_Managed" + classPath + "/" + className, 
				vtableTypeName, pgm);
		//Before returning, we need to:
		//  -make funcptrs for all the slots
		//  -name all the slots
		newTable.initialPopulateVtableStruct();
		//  -apply the vtable to the address
		Boolean result = newTable.applyAtAddress();
		if (!result) {
			Msg.error(OOUtilsVtable.class, "newAutoVtable failed to apply the vtable item");
			//TODO: clean up dead structure & category paths we spawned.
			return null;
		}
		return newTable;
	}

}
