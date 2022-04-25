package ghidra.plugins.ooutils.object.vtable;

import java.lang.String;
import java.util.Vector;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import java.util.stream.Collectors;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeDependencyException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import util.CollectionUtils;
import ghidra.plugins.ooutils.object.ns.OOUtilsPath;
import ghidra.plugins.ooutils.utils.Helpers;

public class OOUtilsVtable {
	
	public Address vtableStartAddress;
	public String vtableTypeName;
	
	int numPtrs;
	int ptrWidth;
	DataType vtableDataType;
	Structure vtableStruct;
	DataTypeManager dtm;
	Listing listing;
	ReferenceManager rm;
	SymbolTable st;
	Program pgm;
	OOUtilsPath path;
	Data vtableInstance;
	
	public OOUtilsVtable(Address start, OOUtilsPath path, Program pgm){
		//Assumes that a vtable that has been created by OOUtils already exists for this type. 
		//If it doesn't, you should call newAutoVtable instead. 
		vtableStartAddress = start;
		this.pgm = pgm;
		this.dtm = pgm.getDataTypeManager();
		this.path = path;
		this.listing = pgm.getListing();
		this.rm = pgm.getReferenceManager();
		this.st = pgm.getSymbolTable();
		this.ptrWidth = dtm.getPointer(new FunctionDefinitionDataType("funcname")).getLength();
		this.vtableTypeName = "vftable"; //TODO: Don't hardcode this -- blocks support for multi-vtable structs.
		this.vtableDataType = dtm.getDataType(path.getClassStructCategoryPath(), vtableTypeName);
		this.vtableInstance = listing.getDataAt(vtableStartAddress);
		this.numPtrs = vtableDataType.getLength()/ptrWidth;
	}
	
	void reloadVtableData() {
		this.vtableDataType = dtm.getDataType(path.getClassStructCategoryPath(), vtableTypeName);
		this.vtableInstance = listing.getDataAt(vtableStartAddress);
	}
	
	public Boolean tryClaimSingleSlot(int index) {
		Function slotFunc = getSlotReferencedFunction(index);
		//Address slotPtrDest = getSlotReferencedAddress(index);
		Vector<Reference> refsTo = Helpers.getNonentryMemoryReferencesToFunction(slotFunc, pgm);
		int refCount = refsTo.size();
		if(refCount != 1) {
			//This function is pointed to by more than just our vtable -- meaning we can't assume ownership
			return false;
		}
		try {
			slotFunc.setParentNamespace(path.getClassNamespace());
		} catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
			Msg.warn(this, String.format("Encountered something weird for class %s, slot# %d", path.getClassName(), index));
		}
		try {
			slotFunc.setCallingConvention("__thiscall");
		} catch (InvalidInputException e) {
			Msg.warn(this, String.format("Could not convert to __thiscall for class %s, slot# %d", path.getClassName(), index));
		}
		return true;
	}
	
	public Address getSlotReferencedAddress(int slotNumber) {
		Data slotInstance = vtableInstance.getComponent(slotNumber);
		Reference[] slotRefArray = slotInstance.getReferencesFrom();
		assert(slotRefArray.length == 1);
		Address toAddr = slotRefArray[0].getToAddress();
		return toAddr;
	}
	
	public Function getSlotReferencedFunction(int slotNumber) {
		return listing.getFunctionAt(getSlotReferencedAddress(slotNumber));
	}
	
	public void claimSlots() {
		int successes = 0;
		for (int i = 0; i < numPtrs; i++) {
			if(tryClaimSingleSlot(i)) {
				successes += 1;
			}
		}
		Msg.info(this, String.format("Successfully claimed ownership of %d funcs for class: %s", successes, path.getClassName()));
	}
	
	public Stream<VFuncImpl> getVtableImplFuncsStream() {
		return IntStream.range(0, numPtrs)
				.mapToObj(
						slot -> new VFuncImpl(getSlotReferencedAddress(slot), this, slot, pgm)
						);
	}
	
	public List<VFuncImpl> getVtableImplFuncs() {
		return getVtableImplFuncsStream() 
				.collect(Collectors.toList());
	}
	
	public Stream<VFuncImpl> getOwnedVFuncImplsStream() {
		return getVtableImplFuncsStream()
				.filter(vfi -> vfi.isOwnedByClass());
	}
	
	public List<VFuncImpl> getOwnedVFuncImpls() {
		return getOwnedVFuncImplsStream()
				.collect(Collectors.toList());
	}
	
	public DataType getVtableDataType() {
		return vtableDataType;
	}
	
	public void updateVtableOwnedImplDefinitions() {
		//Updates virtual member slots *for owned member functions* -- functions not owned by this class are skipped
		StructureDataType updatedVTableType = (StructureDataType) vtableDataType.clone(dtm);
		int ptrSize = Helpers.getArchFuncPtrSize(pgm);
		for(VFuncImpl vslot : CollectionUtils.asIterable(getOwnedVFuncImpls().iterator())) {
			vslot.updateSlotFunctionSignature();
			updatedVTableType.replaceAtOffset(vslot.getSlotOffset(), vslot.getPtrDataType(), ptrSize, vslot.getImplName(), "");
		}
		try {
			dtm.replaceDataType(vtableDataType, updatedVTableType, false);
		} catch (DataTypeDependencyException e) {
			Msg.error(this, String.format("Could not update vtable @ %s", path.getClassStructDtmPathString()));
			return;
		}
		reloadVtableData();
		return;
	}
	
	public Boolean createAtAddress() {
		try {
			listing.createData(vtableStartAddress, vtableDataType);
		} catch (CodeUnitInsertionException | DataTypeConflictException e) {
			Msg.error(this, "Could not spawn new Vtable at the desired location");
			return false;
		}
		vtableInstance = listing.getDataAt(vtableStartAddress);
		return true;
	}
	
	public void initialPopulateVtableStruct()  {
		StructureDataType newDataType = (StructureDataType) vtableDataType.clone(dtm);
		for(int slot = 0; slot < numPtrs; slot++) {
			int offset = slot * ptrWidth;
			String slotName = String.format("slot%d", slot);
			FunctionDefinitionDataType slotFuncDef = new FunctionDefinitionDataType(path.getClassStructCategoryPath(), slotName);
			dtm.addDataType(slotFuncDef, DataTypeConflictHandler.DEFAULT_HANDLER);
			DataType slotDataType = dtm.getPointer(slotFuncDef);
			newDataType.replaceAtOffset(offset, slotDataType, slotDataType.getLength(), slotName, "");
		}
		vtableDataType.replaceWith(newDataType);
		reloadVtableData();
	}
	
	public static OOUtilsVtable newAutoVtable(Address startAddr, int numPtrs, OOUtilsPath path, Program pgm) {
		CategoryPath catPath = path.getClassStructCategoryPath();
		//create a new Ghidra data type for this vtable and add it to dtm:
		DataTypeManager dtm = pgm.getDataTypeManager();
		int PTR_WIDTH = dtm.getPointer(new FunctionDefinitionDataType("funcname")).getLength();
		//CategoryPath dtCategoryPath = new CategoryPath("/OOUtils_Managed" + classPath + "/" + className);
		int vtLength = PTR_WIDTH * numPtrs;
		//TODO: increment vftable numbers?
		String vtableTypeName = "vftable";
		StructureDataType vtableStruct = new StructureDataType(catPath, vtableTypeName, vtLength, dtm);
		dtm.addDataType(vtableStruct, DataTypeConflictHandler.DEFAULT_HANDLER);
		
		//Once that's been added, we're safe to actually construct our class
		OOUtilsVtable newTable = new OOUtilsVtable(startAddr, path, pgm);
		//Before returning, we need to:
		//  -make funcptrs for all the slots
		//  -name all the slots
		newTable.initialPopulateVtableStruct();
		//  -apply the vtable to the address
		Boolean result = newTable.createAtAddress();
		if (!result) {
			Msg.error(OOUtilsVtable.class, "newAutoVtable failed to apply the vtable item");
			//TODO: clean up dead structure & category paths we spawned.
			return null;
		}
		return newTable;
	}
	
	public static OOUtilsVtable newSingleVtable(Address startAddr, OOUtilsPath path, Program pgm) {
		return null;
	}

}
