package mdebug.ecoff;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.exception.AssertException;

import static ghidra.app.util.bin.StructConverter.DWORD;

/**
 * ECOFF Optimization Record
 *
 * These supposedly do not actually exist.
 */
public final class EcoffOptr {

	/** optimization type */
	private final int ot_8;

	/** address where we are moving it to */
	private final int value_24;

	/** points to a symbol or opt entry */
	private final EcoffRndxr rndx;

	/** relative offset this occured */
	private final int offset;

	public static final DataType dataType = getDataType();

	public EcoffOptr(BinaryReader reader) throws IOException {
		final int i = reader.readNextInt();
		final Scalar scalar = new Scalar(8, i, false);
		this.ot_8 = (int) scalar.getValue();
		this.value_24 = i >> 8;
		this.rndx = new EcoffRndxr(reader);
		this.offset = reader.readNextInt();
	}

	/**
	 * @return the ot
	 */
	public int getOt() {
		return ot_8;
	}

	/**
	 * @return the value
	 */
	public int getValue() {
		return value_24;
	}

	/**
	 * @return the rndx
	 */
	public EcoffRndxr getRndx() {
		return rndx;
	}

	/**
	 * @return the offset
	 */
	public int getOffset() {
		return offset;
	}

	private static final DataType getDataType() {
		try {
			Structure struct = new StructureDataType(EcoffHdrr.ECOFF_PATH, "OPTR", 0);
			struct.addBitField(DWORD, 8, "ot", "optimization type");
			struct.addBitField(DWORD, 24, "value", "address where we are moving it to");
			struct.add(EcoffRndxr.dataType, "rndx", "points to a symbol or opt entry");
			struct.add(DWORD, "offset", "relative offset this occured");
			struct.setToMachineAligned();
			return struct;
		} catch (InvalidDataTypeException e) {
			throw new AssertException(e);
		}
	}

}
