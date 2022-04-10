package ooutils.object.vtable;

import java.lang.String;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;

public class OOUtilsVtable {
	static int PTR_WIDTH = 4; //TODO: fetch this from lang spec
	
	Address vtableStartAddress;
	int ptrWidth;
	int numPtrs;
	String classPath;
	String vtableTypeName;
	CategoryPath catPath;
	StructureDataType vtableDataType;
	DataTypeManager dtm;
	Listing listing;
	
	
	public OOUtilsVtable(Address start, String classPath, String vtableTypeName, DataTypeManager dtm, Listing listing){
		//Assumes that a vtable that has been created by OOUtils already exists for this type. 
		//If it doesn't, you should call newAutoVtable instead. 
		vtableStartAddress = start;
		this.dtm = dtm;
		this.vtableTypeName = vtableTypeName;
		this.classPath = classPath;
		this.catPath = new CategoryPath(classPath);
		this.listing = listing;
		
		DataType fetchedDataType = dtm.getDataType(catPath, vtableTypeName);
		this.vtableDataType = (StructureDataType) fetchedDataType;
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
	
	public static OOUtilsVtable newAutoVtable(Address startAddr, int numPtrs, String classPath,
			String className, DataTypeManager dtm, Listing listing) {
		//create a new Ghidra data type for this vtable and add it to dtm:
		CategoryPath dtCategoryPath = new CategoryPath("/OOUtils_Managed" + classPath + "/" + className);
		int vtLength = PTR_WIDTH * numPtrs;
		//TODO: increment vftable numbers?
		String vtableTypeName = "vftable";
		StructureDataType vtableStruct = new StructureDataType(dtCategoryPath, vtableTypeName, vtLength, dtm);
		dtm.addDataType(vtableStruct, DataTypeConflictHandler.DEFAULT_HANDLER);
		
		//Once that's been added, we're safe to actually construct our class
		OOUtilsVtable newTable = new OOUtilsVtable(startAddr, "OOUtils_Managed" + classPath + "/" + className, 
				vtableTypeName, dtm, listing);
		//Before returning, we need to:
		//TODO:  -make funcptrs for all the slots
		//TODO:  -name all the slots
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
