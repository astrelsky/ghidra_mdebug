package mdebug.ecoff;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.DataType;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

class EcoffLongLineNumber implements EcoffLineNumber {

	// According to documentation, the value is 0x800 yet it is a nibble :/
	@SuppressWarnings("unused")
	private final byte constval_4 = (byte) 0x800;

	private final byte count_4;

	private final short delta;

	public static final DataType dataType = getDataType();

	static int SIZE = 3;

	private EcoffLongLineNumber() {
		this.delta = 0;
		this.count_4 = 0;
	}

	EcoffLongLineNumber(BinaryReader reader) throws IOException {
		final byte b = reader.readNextByte();
		this.count_4 = (byte) (b >> 4);
		this.delta = reader.readNextShort();
	}

	@Override
	public int getCount() {
		return this.count_4;
	}

	@Override
	public short getDelta() {
		return this.delta;
	}

	private static final DataType getDataType() {
		try {
			return new EcoffLongLineNumber().toDataType();
		} catch (DuplicateNameException e) {
			Msg.error(EcoffLongLineNumber.class, e);
			return null;
		}
	}

    @Override
    public DataType toDataType() throws DuplicateNameException {
        DataType dt = StructConverterUtil.toDataType(this);
        try {
            dt.setNameAndCategory(EcoffHdrr.ECOFF_PATH, "LINER");
        } catch (InvalidNameException e) {
            // not invalid
        }
        return dt;
    }
}
