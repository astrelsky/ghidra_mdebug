package mdebug.ecoff;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.exception.AssertException;

import static ghidra.app.util.bin.StructConverter.WORD;

/**
 * ECOFF External Symbol Record
 */
public final class EcoffExtr {

	private static final DataType BOOL = BooleanDataType.dataType;

	/** symbol is a jump table entry for shlibs */
	private final boolean jmptbl;

	/** symbol is a cobol main procedure */
	private final boolean cobol_main;

	/** symbol is weak external */
	private final boolean weakext;

	/** symbol is delta C++ symbol */
	private final boolean deltacplus;

	/** symbol may be defined multiple times */
	private final boolean multiext;

	/** where the iss and index fields point into */
	private final short ifd;

	/** symbol for the external */
	private final EcoffSymr symr;

	private final EcoffStringTable sTable;

	public static final DataType dataType = getDataType();

	public EcoffExtr(BinaryReader reader, EcoffStringTable sTable) throws IOException {
		final Scalar scalar = new Scalar(4, reader.readNextShort(), false);
		this.jmptbl = scalar.testBit(1);
		this.cobol_main = scalar.testBit(2);
		this.weakext = scalar.testBit(3);
		this.deltacplus = scalar.testBit(4);
		this.multiext = scalar.testBit(5);
		this.ifd = reader.readNextShort();
		this.symr = new EcoffSymr(reader);
		this.sTable = sTable;
	}

	/**
	 * @return the filename
	 * @throws IOException
	 */
	public String getFileName() throws IOException {
		return symr.getSymbolName();
	}

	String getSymbolName(int index) throws IOException {
		return sTable.getString(index);
	}

	@Override
	public String toString() {
		try {
			String fName = getFileName();
			if (fName != null && !fName.equals("")) {
				return fName;
			}
		} catch (IOException e) {
			// returning default toString
		}
		return super.toString();
	}

	/**
	 * @return the jmptbl
	 */
	public boolean isJmptbl() {
		return jmptbl;
	}

	/**
	 * @return the cobol_main
	 */
	public boolean isCobolMain() {
		return cobol_main;
	}

	/**
	 * @return the weakext
	 */
	public boolean isWeakExt() {
		return weakext;
	}

	/**
	 * @return the deltacplus
	 */
	public boolean isDeltacplus() {
		return deltacplus;
	}

	/**
	 * @return the multiext
	 */
	public boolean isMultiext() {
		return multiext;
	}

	/**
	 * @return the ifd
	 */
	public short getIfd() {
		return ifd;
	}

	/**
	 * @return the symr
	 */
	public EcoffSymr getSymr() {
		return symr;
	}

	private static final DataType getDataType() {
		try {
			Structure struct = new StructureDataType(EcoffHdrr.ECOFF_PATH, "EXTR", 0);
			struct.addBitField(BOOL, 1, "jmptbl", " symbol is a jump table entry for shlibs");
			struct.addBitField(BOOL, 1, "cobol_main", " symbol is a cobol main procedure");
			struct.addBitField(BOOL, 1, "weakext", " symbol is weak external");
			struct.addBitField(BOOL, 1, "deltacplus", " symbol is delta C++ symbol");
			struct.addBitField(BOOL, 1, "multiext", " symbol may be defined multiple times");
			struct.addBitField(WORD, 11, "reserved", "reserved for future use");
			struct.add(WORD, "ifd", " where the iss and index fields point into");
			struct.add(EcoffSymr.dataType, "symr", " symbol for the external");
			struct.setToMachineAlignment();
			return struct;
		} catch (InvalidDataTypeException e) {
			throw new AssertException(e);
		}
	}
}
