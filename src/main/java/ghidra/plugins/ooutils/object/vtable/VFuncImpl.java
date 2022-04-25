package ghidra.plugins.ooutils.object.vtable;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeDependencyException;
import ghidra.program.model.data.FunctionDefinitionDataType;

import ghidra.util.Msg;

import ghidra.plugins.ooutils.object.ns.OOUtilsPath;
import ghidra.plugins.ooutils.utils.Helpers;

public class VFuncImpl {
	Program pgm;
	Listing lst;
	Function func;
	Address funcAddr;
	OOUtilsVtable owner;
	int slotNum;
	OOUtilsPath path;
	DataTypeManager dtm;
	
	public VFuncImpl(Address addr, OOUtilsVtable owner, int slotNum, Program pgm) {
		this.funcAddr = addr;
		this.pgm = pgm;
		this.owner = owner;
		this.slotNum = slotNum;
		
		this.lst = pgm.getListing();
		this.path = owner.path;
		this.func = lst.getFunctionAt(addr);
		this.dtm = pgm.getDataTypeManager();
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
	
	public Boolean isOwnedByClass() {
		//returns true if this function is a member of the class's namespace
		return func.getParentNamespace() == path.getClassNamespace();
	}
	
	public void updateSlotFunctionSignature() {
		//TODO: see if we can remove this assert
		assert(isOwnedByClass());
		DataType currentSlotDef = dtm.getDataType(path.getClassStructCategoryPath(), getSlotName());
		FunctionDefinitionDataType fsdt = new FunctionDefinitionDataType(func.getSignature());
		try {
			dtm.replaceDataType(currentSlotDef, fsdt, false);
		} catch (DataTypeDependencyException e) {
			Msg.error(this, String.format("Failed to update slot #%d definition for vtable w/ path %s", slotNum, path.getClassName()));
			return;
		}
	}
}
