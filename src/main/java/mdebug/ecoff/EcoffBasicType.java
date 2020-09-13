package mdebug.ecoff;

import ghidra.program.model.data.DataType;

public enum EcoffBasicType implements EcoffEnumConverter {
	
	NIL((byte) 0),
	ADR((byte) 1),
	CHAR((byte) 2),
	UCHAR((byte) 3),
	SHORT((byte) 4),
	USHORT((byte) 5),
	INT((byte) 6),
	UINT((byte) 7),
	LONG((byte) 8),
	ULONG((byte) 9),
	FLOAT((byte) 10),
	DOUBLE((byte) 11),
	STRUCT((byte) 12),
	UNION((byte) 13),
	ENUM((byte) 14),
	TYPEDEF((byte) 15),
	RANGE((byte) 16),
	SET((byte) 17),
	COMPLEX((byte) 18),
	DCOMPLEX((byte) 19),
	INDIRECT((byte) 20),
	FIXEDDEC((byte) 21),
	FLOATDEC((byte) 22),
	STRING((byte) 23),
	BIT((byte) 24),
	PICTURE((byte) 25),
	VOID((byte) 26),
	LONGLONG((byte) 27),
	ULONGLONG((byte) 28),
	UNDEFINED((byte) 29), // I made this one up. It'll never be returned
	LONG64((byte) 30),
	ULONG64((byte) 31),
	LONGLONG64((byte) 32),
	ULONGLONG64((byte) 33),
	ADR64((byte) 34),
	INT64((byte) 35),
	UINT64((byte) 36),
	MAX((byte) 64);
	
	public static final DataType dataType =
		EcoffEnumConverterUtil.toDataType(EcoffBasicType.class);

	private final byte value;

	private EcoffBasicType(byte value) {
		this.value = value;
	}

	@Override
	public long getValue() {
		return value;
	}

	public static EcoffBasicType toEnum(int value) {
		if (value >= NIL.value && value <= UINT64.value && value != UNDEFINED.value) {
			return values()[value];
		}
		if (value == MAX.value) {
			return MAX;
		}
		return null;
	}
	
}
