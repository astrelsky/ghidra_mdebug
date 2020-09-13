package mdebug.ecoff;

import ghidra.program.model.data.DataType;

public enum EcoffTypeQualifier implements EcoffEnumConverter {
	NIL((byte) 0),
	PTR((byte) 1),
	PROC((byte) 2),
	ARRAY((byte) 3),
	FAR((byte) 4),
	VOL((byte) 5),
	CONST((byte) 6),
	MAX((byte) 8);
	
	public static final DataType dataType =
		EcoffEnumConverterUtil.toDataType(EcoffTypeQualifier.class);

	private final byte value;

	private EcoffTypeQualifier(byte value) {
		this.value = value;
	}

	@Override
	public long getValue() {
		return value;
	}

	public static EcoffTypeQualifier toEnum(long value) {
		if (value <= CONST.value && value >= 0) {
			return values()[(int) value];
		}
		if (value == MAX.value) {
			return MAX;
		}
		return null;
	}
	
}
