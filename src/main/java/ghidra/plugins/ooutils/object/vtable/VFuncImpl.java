package ghidra.plugins.ooutils.object.vtable;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeDependencyException;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.plugins.ooutils.object.ns.OOUtilsPath;
import ghidra.plugins.ooutils.utils.Helpers;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.RefType;

public class VFuncImpl {
	Program pgm;
	Listing lst;
	Function func;
	Address funcAddr;
	OOUtilsVtable owner;
	int slotNum;
	OOUtilsPath path;
	DataTypeManager dtm;
	ReferenceManager rm;
	
	public VFuncImpl(Address addr, OOUtilsVtable owner, int slotNum, Program pgm) {
		this.funcAddr = addr;
		this.pgm = pgm;
		this.owner = owner;
		this.slotNum = slotNum;
		
		this.lst = pgm.getListing();
		this.path = owner.path;
		this.func = lst.getFunctionAt(addr);
		this.dtm = pgm.getDataTypeManager();
		this.rm = pgm.getReferenceManager();
	}
	
	public String getImplName() {
		return func.getName(false);
	}
	
	public String getSlotName() {
		return String.format("slot%d", slotNum);
	}
	
	public DataType getSlotDataType() {
		return dtm.getDataType(path.getClassStructCategoryPath(), getSlotName());
	}
	
	public DataType getPtrDataType() {
		return dtm.getPointer(getSlotDataType());
	}
	
	public int getSlotOffset() {
		int ptrWidth = Helpers.getArchFuncPtrSize(pgm);
		return slotNum * ptrWidth;
	}
	
	public Address getSlotResidentAddress() {
		return owner.getVtableStartAddress().add(getSlotOffset());
	}
	
	public Boolean isOwnedByClass() {
		//returns true if this function is a member of the class's namespace
		return func.getParentNamespace() == path.getClassNamespace();
	}
	
	public void clearSlotRef() {
		rm.removeAllReferencesFrom(getSlotResidentAddress());
	}
	
	public void makeSlotRef() {
		rm.addMemoryReference(getSlotResidentAddress(), funcAddr, RefType.DATA, SourceType.USER_DEFINED, 0);
	}
	
	public Boolean destroy(TaskMonitor mon) {
		return dtm.remove(getSlotDataType(), mon);
	}
	
	public void updateSlotFunctionSignature() {
		//TODO: see if we can remove this assert
		assert(isOwnedByClass());
		DataType currentSlotDef = getSlotDataType();
		FunctionDefinitionDataType fsdt = new FunctionDefinitionDataType(func.getSignature());
		try {
			fsdt.setName(getSlotName());
		} catch (InvalidNameException e1) {
			Msg.error(fsdt, "How even??? Something's bad, contact dev pls");
			return;
		}
		try {
			dtm.replaceDataType(currentSlotDef, fsdt, false);
		} catch (DataTypeDependencyException e) {
			Msg.error(this, String.format("Failed to update slot #%d definition for vtable w/ path %s", slotNum, path.getClassName()));
			return;
		}
	}
}
