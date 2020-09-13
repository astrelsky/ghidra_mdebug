package mdebug.ecoff;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.DataType;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

class EcoffShortLineNumber implements EcoffLineNumber {

	private byte delta_4;

	private byte count_4;

	public static final DataType dataType = getDataType();

	static int SIZE = 1;

	private EcoffShortLineNumber() {
		this.delta_4 = 0;
		this.count_4 = 0;
	}

	EcoffShortLineNumber(BinaryReader reader) throws IOException {
		final byte b = reader.readNextByte();
		this.delta_4 = (byte) new Scalar(4, b, true).getSignedValue();
		this.count_4 = (byte) (b >> 4);
	}

	@Override
	public int getCount() {
		return this.count_4;
	}

	@Override
	public short getDelta() {
		return this.delta_4;
	}

	private static final DataType getDataType() {
		try {
			return new EcoffShortLineNumber().toDataType();
		} catch (DuplicateNameException e) {
			Msg.error(EcoffShortLineNumber.class, e);
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
