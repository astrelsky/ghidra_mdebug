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
 * ECOFF Relative Symbol Record
 *
 * This is a record which is used to point
 * to another ECOFF record.
 */
final class EcoffRndxr {

	/** index into the file indirect table */
	private final int rfd;

	/** index into sym/aux/iss tables */
	private final int index;

	public static final DataType dataType = getDataType();

	EcoffRndxr(BinaryReader reader) throws IOException {
		final int i = reader.readNextInt();
		final Scalar scalar = new Scalar(12, i, false);
		this.rfd = (int) scalar.getValue();
		this.index = i >> 12;
	}

	EcoffRndxr(final int data) {
		final Scalar scalar = new Scalar(12, data, false);
		this.rfd = (int) scalar.getValue();
		this.index = data >> 12;
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

	public boolean isEscape() {
		return (rfd & 0xfff) == 0xfff;
	}

	private static final DataType getDataType() {
		try {
			Structure struct = new StructureDataType(EcoffHdrr.ECOFF_PATH, "RNDXR", 0);
			struct.addBitField(DWORD, 12, "rfd", "index into the file indirect table");
			struct.addBitField(DWORD, 20, "index", "index into sym/aux/iss tables");
			struct.setToMachineAligned();
			return struct;
		} catch (InvalidDataTypeException e) {
			throw new AssertException(e);
		}
	}

}
