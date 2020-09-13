package mdebug.ecoff;

import ghidra.app.util.bin.StructConverter;

public interface EcoffLineNumber extends StructConverter {
	
	int getCount();

	short getDelta();
}
