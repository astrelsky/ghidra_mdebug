package mdebug.ecoff;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

class EcoffStringTable {

	private final BinaryReader reader;

	EcoffStringTable(BinaryReader reader) {
		this.reader = reader;
	}

	String getString(long index) throws IOException {
		return reader.readAsciiString(index);
	}
}
