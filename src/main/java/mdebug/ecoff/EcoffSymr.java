package mdebug.ecoff;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.exception.AssertException;

import static ghidra.app.util.bin.StructConverter.*;

/**
 * The ECOFF Local Symbol
 */
public final class EcoffSymr {

	/** index into String Space of name */
	private final int iss;

	/** value of symbol */
	private final int value;

	/** symbol type */
	private final EcoffSt st;

	/** storage class - text, data, etc */
	private final EcoffSc sc;

	// max aux entries?
	/** index into sym/aux table */
	private final int index;

	private EcoffFdr file;
	private EcoffExtr extFile;
	private static final int SIZE = 12;

	public static final DataType dataType = getDataType();
	private static final int CODE_MASK = 0x8F300;

	public EcoffSymr(BinaryReader reader) throws IOException {
		this.iss = reader.readNextInt();
		this.value = reader.readNextInt();

		final int symbol = reader.readNextInt();
		Scalar scalar = new Scalar(6, symbol, false);
		this.st = EcoffSt.toEnum(scalar.getValue());
		scalar = new Scalar(5, symbol >> 6, false);
		this.sc = EcoffSc.toEnum(scalar.getValue());
		this.index = symbol >> 12;
	}

	/**
	 * @return the filename
	 * @throws IOException
	 */
	public String getSymbolName() throws IOException {
		if (iss == -1) {
			// symbol name is nil
			return "";
		}

		//TODO concat ext and file
		if (file != null) {
			return file.getSymbolName(iss);
		}
		if (extFile != null) {
			return extFile.getSymbolName(iss);
		}
		return "";
	}

	@Override
	public String toString() {
		try {
			String name = getSymbolName();
			if (name != null && !name.equals("")) {
				return name;
			}
		} catch (IOException e) {
			// returning default toString
		}
		return super.toString();
	}

	void setFile(EcoffFdr file) {
		this.file = file;
	}

	void setExtFile(EcoffExtr extFile) {
		this.extFile = extFile;
	}

	/**
	 * Gets the ECOFF File Descriptor record for the file which
	 * contained this symbol or null if it's an external symbol.
	 *
	 * @return the EcoffFdr for this symbol
	 */
	public EcoffFdr getFile() {
		return file;
	}

	public EcoffAuxu getAuxu() {
		if (file != null && index != -1) {
			return file.getAuxu(index);
		}
		return null;
	}

	/**
	 * @return the iss
	 */
	public int getIss() {
		return iss;
	}

	/**
	 * @return the value
	 */
	public int getValue() {
		return value;
	}

	/**
	 * @return the st
	 */
	public EcoffSt getSt() {
		return st;
	}

	/**
	 * @return the sc
	 */
	public EcoffSc getSc() {
		return sc;
	}

	/**
	 * @return the index
	 */
	public int getIndex() {
		return index;
	}

	private static final DataType getDataType() {
		try {
			Structure struct = new StructureDataType(EcoffHdrr.ECOFF_PATH, "SYMR", 0);
			struct.add(DWORD, "iss", "index into String Space of name");
			struct.add(DWORD, "value", "value of symbol");
			struct.addBitField(EcoffSt.dataType, 6, "st", "symbol type");
			struct.addBitField(EcoffSc.dataType, 5, "sc", "storage class - text, data, etc");
			struct.addBitField(BYTE, 1, "reserved", null);

			// max aux entries?
			struct.addBitField(DWORD, 20, "index", "index into sym/aux table");
			struct.setToMachineAlignment();
			return struct;
		} catch (InvalidDataTypeException e) {
			throw new AssertException(e);
		}
	}

	public static int getDataTypeLength() {
		return SIZE;
	}

	public boolean isStab() {
		return (index & 0xFFF00) == CODE_MASK;
	}
}
