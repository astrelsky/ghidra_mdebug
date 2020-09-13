package mdebug.ecoff;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

import static ghidra.app.util.bin.StructConverter.DWORD;

/**
 * ECOFF Dense Number Record
 * 
 * Unused in object files
 */
public final class EcoffDnr {

	private final int rfd;

	private final int index;

	public static final DataType dataType = getDataType();

	public EcoffDnr(BinaryReader reader) throws IOException {
		this.rfd = reader.readNextInt();
		this.index = reader.readNextInt();
	}

	/**
	 * @return the rfd
	 */
	public int getRfd() {
		return rfd;
	}

	/**
	 * @return the index
	 */
	public int getIndex() {
		return index;
	}

	private static final DataType getDataType() {
		Structure struct = new StructureDataType(EcoffHdrr.ECOFF_PATH, "DNR", 0);
		struct.add(DWORD, "rfd", null);
		struct.add(DWORD, "index", null);
		return struct;
	}

}
