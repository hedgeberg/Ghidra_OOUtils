package ghidra.plugins.ooutils.object.ns;

import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.plugins.ooutils.utils.Helpers;
import ghidra.app.util.NamespaceUtils;
import java.util.Vector;
import java.util.Arrays;

public class OOUtilsPath {
	
	Program pgm;
	String combinedNsAndClassName;
	String className;
	String nsFullName;
	String oldClassName;
	Vector<String> nsPieces;
	
	public OOUtilsPath(String combinedNsAndClassName, Program pgm) {
		this.pgm = pgm;
		this.combinedNsAndClassName = combinedNsAndClassName;
		this.nsPieces = new Vector<String>(Arrays.asList(combinedNsAndClassName.split("::")));
		this.className = nsPieces.lastElement();
		this.nsPieces.removeElementAt(this.nsPieces.size() - 1);
		this.nsFullName = String.join("::", this.nsPieces);
	}
	
	public static OOUtilsPath fromVtableAddress(Address vtableStartAddr, Program pgm) {
		SymbolTable st = pgm.getSymbolTable();
		Symbol vtableSymbol = st.getPrimarySymbol(vtableStartAddr);
		String classNsStr = vtableSymbol.getParentNamespace().getName();
		return new OOUtilsPath(classNsStr, pgm);
	}
	
	public void ensureParentNamespacePath() throws InvalidInputException {
		Namespace globalNs = pgm.getGlobalNamespace();
		if(!nsFullName.isEmpty()) {
			NamespaceUtils.createNamespaceHierarchy(nsFullName, globalNs, pgm, SourceType.USER_DEFINED);
		}
	}
	
	public Namespace getParentNamespace() {
		return Helpers.resolveStringToNamespace(nsFullName, pgm);
	}
	
	public GhidraClass getClassNamespace() {
		return (GhidraClass) Helpers.resolveStringToNamespace(combinedNsAndClassName, pgm);
	}
	
	public String getParentNsString() {
		return nsFullName;
	}
	
	public String getClassNsString() {
		return combinedNsAndClassName;
	}
	
	public String getClassName() {
		return className;
	}
	
	public void changeClassName(String newName, TaskMonitor mon) {
		oldClassName = className;
		className = newName;
	}
	
	public void revertClassName() {
		assert(oldClassName != null);
		className = oldClassName;
	}
	
	public String getContainingDtmPathString() {
		String pathstr = new String("/OOUtils_Managed");
		for(String piece : nsPieces) {
			pathstr += ("/" + piece);
		}
		return pathstr;
	}
	
	public CategoryPath getContainingCategoryPath() {
		String pathstr = getContainingDtmPathString();
		return new CategoryPath(pathstr);
	}
	
	public String getClassStructDtmPathString() {
		return getContainingDtmPathString() + "/" + className;
	}
	
	public CategoryPath getClassStructCategoryPath() {
		return new CategoryPath(getClassStructDtmPathString());
	}
}
