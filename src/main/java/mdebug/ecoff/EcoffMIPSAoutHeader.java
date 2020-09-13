package mdebug.ecoff;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

import static ghidra.app.util.bin.StructConverter.*;

public class EcoffMIPSAoutHeader {

	public final static int SIZEOF = 56;

	/** magic value - machine specific */
	private final short magic;
	/** version stamp */
	private final short vstamp;
	/** text size in bytes */
	private final int tsize;
	/** initialized data size in bytes */
	private final int dsize;
	/** uninitialized data size in bytes */
	private final int bsize;
	/** entry point */
	private final int entry;
	/** base of text used for this file */
	private final int textStart;
	/** base of data used for this file */
	private final int dataStart;
	/** base of bss used for this file */
	private final int bssStart;
	/** general purpose register mask */ 
	private final int gprmask;
	/** co-processor register mask */
	private final int[] cprmask;
	/** gp value used for this object */ 
	private final int gpValue;

	public static final DataType dataType = getDataType();

	EcoffMIPSAoutHeader(BinaryReader reader) throws IOException {
		magic = reader.readNextShort();
		vstamp = reader.readNextShort();
		tsize = reader.readNextInt();
		dsize = reader.readNextInt();
		bsize = reader.readNextInt();
		entry = reader.readNextInt();
		textStart = reader.readNextInt();
		dataStart = reader.readNextInt();
		bssStart = reader.readNextInt();
		gprmask = reader.readNextInt();
		cprmask = reader.readNextIntArray(4);
		gpValue = reader.readNextInt();
	}

	public short getMagic() {
		return magic;
	}

	public short getVersionStamp() {
		return vstamp;
	}

	public int getTextSize() {
		return tsize;
	}

	public int getInitializedDataSize() {
		return dsize;
	}

	public int getUninitializedDataSize() {
		return bsize;
	}

	public int getEntry() {
		return entry;
	}

	public int getTextStart() {
		return textStart;
	}

	public int getInitializedDataStart() {
		return dataStart;
	}

	private static DataType getDataType() {
		Array array = new ArrayDataType(DWORD, Integer.BYTES, Integer.BYTES);
		Structure struct = new StructureDataType(EcoffHdrr.ECOFF_PATH, "AOUTHDR", 0);
		struct.add(WORD, "magic", "magic value - machine specific");
		struct.add(WORD, "vstamp", "version stamp");
		struct.add(DWORD, "tsize", "text size in bytes");
		struct.add(DWORD, "dsize", "initialized data size in bytes");
		struct.add(DWORD, "bsize", "uninitialized data size in bytes");
		struct.add(DWORD, "entry", "entry point");
		struct.add(DWORD, "text_start", "base of text used for this file");
		struct.add(DWORD, "data_start", "base of data used for this file");
		struct.add(DWORD, "bss_start", "base of bss used for this file");
		struct.add(DWORD, "gprmask", "general purpose register mask");
		struct.add(array, "cprmask", null);
		struct.add(DWORD, "gp_value", null);
		return struct;
	}

	public int getUnitializedDataStart() {
		return bssStart;
	}

	/**
	 * Returns the general purpose register mask.
	 * @return the general purpose register mask
	 */
	public int getGprMask() {
		return gprmask;
	}

	/**
	 * Returns the co-processor register masks.
	 * @return the co-processor register masks
	 */
	public int[] getCprMask() {
		return cprmask;
	}

	/**
	 * Returns the GP value.
	 * @return the GP value
	 */
	public int getGpValue() {
		return gpValue;
	}
}
