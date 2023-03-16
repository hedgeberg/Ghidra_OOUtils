package ghidra.plugins.ooutils.object.vtable;

import java.lang.String;
import java.util.Vector;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import java.util.stream.Collectors;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeDependencyException;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.VariableSizeException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import util.CollectionUtils;
import ghidra.plugins.ooutils.object.ns.OOUtilsPath;
import ghidra.plugins.ooutils.utils.Helpers;

public class OOUtilsVtable {
	
	public Address vtableStartAddress;
	public String vtableTypeName;
	
	int numPtrs;
	int ptrWidth;
	DataType vtableDataType;
	Category vtableChildrenCategory;
	DataTypeManager dtm;
	Listing listing;
	ReferenceManager rm;
	SymbolTable st;
	Program pgm;
	OOUtilsPath path;
	Data vtableInstance;
	StructureDataType updatingDataType;
	
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
		this.vtableChildrenCategory = dtm.getCategory(path.getClassStructCategoryPath());
		this.updatingDataType = null;
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
		if(slotRefArray.length == 0) {
			try {
				Address slotAddr = slotInstance.getAddress();
				Address refAddr = slotAddr.getAddressSpace().getAddress(slotInstance.getVarLengthInt(0, ptrWidth));
				return refAddr;
			} catch (Exception e) {
				//TODO get rid of this mess, jfc
				//HACK kluuuuuudge
				assert(false);
			}
			return null;
		} else {
			assert(slotRefArray.length == 1);
			Address toAddr = slotRefArray[0].getToAddress();
			return toAddr;
		}
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
	
	private VFuncImpl getVFuncImplBySlotNumber(int slotNumber) {
		assert((slotNumber >= 0) && (slotNumber < numPtrs));
		return getVtableImplFuncs().get(slotNumber);
	}
	
	public DataType getVtableDataType() {
		return vtableDataType;
	}
	
	public Address getVtableStartAddress() {
		return vtableStartAddress;
	}
	
	public int getVtableSize() {
		return numPtrs * ptrWidth;
	}
	
	private void insertSingleSlot(int slotNum) {
		//Private method to inject a new vfunc type into the selected vtable slot. rquires that the vtable already has space for it.
		int offset = slotNum * ptrWidth;
		String slotName = String.format("slot%d", slotNum);
		FunctionDefinitionDataType slotFuncDef = new FunctionDefinitionDataType(path.getClassStructCategoryPath(), slotName);
		dtm.addDataType(slotFuncDef, DataTypeConflictHandler.DEFAULT_HANDLER);
		DataType slotDataType = dtm.getPointer(slotFuncDef);
		updatingDataType.replaceAtOffset(offset, slotDataType, slotDataType.getLength(), slotName, "");
	}
	
	private void startDTUpdate() {
		//Private method that populates the updatingDataType field, indicating a DataType update has started
		updatingDataType = (StructureDataType) vtableDataType.clone(dtm);
	}
	
	private void endDTUpdate() {
		//Private method that propogates all changes made during the DT update to the database, clears the updating field, and refreshes the struct
		vtableDataType.replaceWith(updatingDataType);
		updatingDataType = null;
		reloadVtableData();
	}
	
	public void clearForNewSlot() {
		Address afterVtable = vtableInstance.getAddress().add(getVtableSize());
		listing.clearCodeUnits(afterVtable, afterVtable.add(ptrWidth - 1), true); //-1 because clearCodeUnits is inclusive
	}
	
	public void growVtableSingle() throws VariableSizeException {
		//Add a single slot to the vtable
		
		//Step 1: Check if there's data after this slot at the physical vtable offset, and throw an exception if so
		Address toBeConsumedStart = vtableInstance.getAddress();
		toBeConsumedStart = toBeConsumedStart.add(vtableDataType.getLength());
		Address toBeConsumedEnd = toBeConsumedStart.add(ptrWidth - 1); //-1 because AddressSet is inclusive
		AddressSet toBeConsumed = new AddressSet(toBeConsumedStart, toBeConsumedEnd);
		for(Data elem : listing.getData(toBeConsumed, true)) {
			if(elem.isDefined()) {
				throw new VariableSizeException(String.format("Data exists @ {}",elem.getAddress()));
			}
		}
		//Step 2: add field to vtable struct
		startDTUpdate();
		updatingDataType.growStructure(ptrWidth);
		insertSingleSlot(numPtrs);
		numPtrs += 1;
		endDTUpdate();
		//Step 3: fix up references
		VFuncImpl slotFunc = getVFuncImplBySlotNumber(numPtrs - 1);
		slotFunc.clearSlotRef();
		slotFunc.makeSlotRef();
		tryClaimSingleSlot(numPtrs - 1);
	}
	
	public void shrinkVtableSingle(TaskMonitor mon) throws VariableSizeException {
		//Remove a single slot from the vtable
		
		//Step 1: ensure we aren't trying to subtract the last vtable slot
		if(numPtrs == 1) {
			throw new VariableSizeException(String.format("Can't shrink Vtable with size 1"));
		}
		assert(numPtrs >= 2);
		//Step 2: shrink Vtable
		int toBeDestroyed = numPtrs - 1;
		VFuncImpl slotFunc = getVFuncImplBySlotNumber(toBeDestroyed);
		slotFunc.clearSlotRef();
		startDTUpdate();
		updatingDataType.deleteAtOffset(toBeDestroyed * ptrWidth);
		endDTUpdate();
		numPtrs -= 1;
		//Step 3: clean up slot's vfunc data type
		Boolean result = slotFunc.destroy(mon);
		assert(result);
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
		} catch (CodeUnitInsertionException e) {
			Msg.error(this, "Could not spawn new Vtable at the desired location");
			return false;
		}
		vtableInstance = listing.getDataAt(vtableStartAddress);
		return true;
	}
	
	public Boolean changeClassName(String newName, TaskMonitor mon) throws InvalidNameException {

		//1d: check for a conflicting class datatype
		if(dtm.getDataType(path.getContainingCategoryPath(), newName) != null) {
			return false;
		}
		//1e: check for a conflicting class category
		path.changeClassName(newName, mon);
		if(dtm.containsCategory(path.getClassStructCategoryPath())) {
			path.revertClassName();
			return false;
		}
		path.revertClassName();
		//Step 2: Now we should be able to do this without any exceptions. 
		//2a: change the name of the folder containing all the class vfuncs
		try {
			vtableChildrenCategory.setName(newName);
		} catch (DuplicateNameException  e) {
			// this *should* be impossible thanks to our checks
			assert(false);
		}
		return true;
	}
	
	public void initialPopulateVtableStruct()  {
		startDTUpdate();
		for(int slot = 0; slot < numPtrs; slot++) {
			insertSingleSlot(slot);
		}
		endDTUpdate();
	}
	
	// struct foo_t {
	//		void * foo; 
	//		void * bar;
	// }
	
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
		//Have to create the category manually so that dtm.getCategory doesn't return a null pointer. 
		dtm.createCategory(path.getClassStructCategoryPath());
		//Once that's been added, we're safe to actually construct our class
		Address endAddr = startAddr.add(vtLength-1);
		//TODO: need to check for data earlier, then bail out. 
		pgm.getListing().clearCodeUnits(startAddr, endAddr, true);
		pgm.getReferenceManager().removeAllReferencesFrom(startAddr, endAddr);
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
