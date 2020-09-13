package mdebug.ecoff;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;

import static ghidra.app.util.bin.StructConverter.DWORD;

public class EcoffAuxu {

	private int data;

	public static final DataType dataType = toDataType();

	public EcoffAuxu(BinaryReader reader) throws IOException {
		this.data = reader.readNextInt();
	}

	public static DataType toDataType() {
		Union union = new UnionDataType(EcoffHdrr.ECOFF_PATH, "AUXU");
		union.add(EcoffTir.dataType, "ti", "type information record");
		union.add(EcoffRndxr.dataType, "rndx", "relative index into symbol table");
		union.add(DWORD, "dnLow", "low dimension");
		union.add(DWORD, "dnHigh", "high dimension");
		union.add(DWORD, "isym", "symbol table index (end of proc)");
		union.add(DWORD, "iss", "index into string space (not used)");
		union.add(DWORD, "width", "width for non-default sized struc fields");
		union.add(DWORD, "count", "count of ranges for variant arm");
		return union;
	}

	public int getDataAsInt() {
		return data;
	}

	public EcoffTir getTir() {
		return new EcoffTir(data);
	}

	public EcoffRndxr getRndxr() {
		return new EcoffRndxr(data);
	}

}
