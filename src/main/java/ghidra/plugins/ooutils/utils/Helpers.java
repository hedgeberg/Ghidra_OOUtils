package ghidra.plugins.ooutils.utils;

import java.lang.String;
import java.util.Arrays;

import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.Namespace;

public class Helpers {
	public static int getArchFuncPtrSize(Program pgm) {
		return pgm.getDataTypeManager().getPointer(new FunctionDefinitionDataType("funcname")).getLength();
	}
	
	public static String[] splitUpNamespaceString(String ns_str) {
		if((ns_str == null) || (ns_str.isEmpty())) {
			return new String[] {};
		}
		return ns_str.split("::");
	}
	
	public static String[] splitOutClassFromNamespace(String className) {
		String[] nsParts = splitUpNamespaceString(className);
		String classNameSeparated = nsParts[nsParts.length-1];
		String ns_str;
		if (nsParts.length > 1) {
			String [] nsSeparated = Arrays.copyOfRange(nsParts, 0, nsParts.length - 1);
			ns_str = String.join("::", nsSeparated);
		} else {
			ns_str = new String("");
		}
		return new String[] {classNameSeparated, ns_str};
	}
	
	public static Namespace resolveStringToNamespace(String ns_str, Program pgm) {
		SymbolTable st = pgm.getSymbolTable();
		Namespace ns = null;
		for(String name : splitUpNamespaceString(ns_str)) {
			ns = st.getNamespace(name, ns);
		}
		return ns;
	}
	
	public static String nsPathToSlashPath(String ns_str) {
		String path = new String("");
		for(String name : splitUpNamespaceString(ns_str)) {
			path += ("/" + name);
		}
		return path;
	}
}
