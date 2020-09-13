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

import static ghidra.app.util.bin.StructConverter.DWORD;

public class EcoffRelocation {

	/** (virtual) address of reference */
	private final int r_vaddr;

	/** index into symbol table */
	private final int r_symndx;

	/** relocation type */
	private final int r_type;

	/** external flag */
	private final boolean r_extern;

	public static final DataType dataType = getDataType();

	EcoffRelocation(BinaryReader reader) throws IOException {
		r_vaddr = reader.readNextInt();
		final int i = reader.readNextInt();
		Scalar scalar = new Scalar(24, i, false);
		r_symndx = (int) scalar.getValue();
		scalar = new Scalar(4, i >> scalar.bitLength(), false);
		r_type = (int) scalar.getValue();
		r_extern = (i >> 31) == 1;
	}

	private static final DataType getDataType() {
		try {
			Structure struct = new StructureDataType(EcoffHdrr.ECOFF_PATH, "reloc", 0);
			struct.add(DWORD, "r_vaddr", "virtual address of reference");
			struct.addBitField(DWORD, 24, "r_symndx", "index into symbol table");
			struct.addBitField(DWORD, 3, "r_reserved", null);
			struct.addBitField(DWORD, 4, "r_type", "relocation type");
			struct.addBitField(BooleanDataType.dataType, 1, "r_extern", "external flag");
			struct.setToMachineAlignment();
			return struct;
		} catch (InvalidDataTypeException e) {
			throw new AssertException(e);
		}
	}

	/**
	 * @return the r_vaddr
	 */
	public int getVaddr() {
		return r_vaddr;
	}

	/**
	 * @return the r_symndx
	 */
	public int getSymndx() {
		return r_symndx;
	}

	/**
	 * @return the r_type
	 */
	public int getType() {
		return r_type;
	}

	/**
	 * @return the r_extern
	 */
	public boolean isExtern() {
		return r_extern;
	}

}
