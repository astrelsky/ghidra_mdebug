package mdebug.ecoff;

import ghidra.program.model.data.DataType;

public enum EcoffSt implements EcoffEnumConverter {
	NIL(0),
	GLOBAL(1),
	STATIC(2),
	PARAM(3),
	LOCAL(4),
	LABEL(5),
	PROC(6),
	BLOCK(7),
	END(8),
	MEMBER(9),
	TYPEDEF(10),
	FILE(11),
	REGRELOC(12),
	FORWARD(13),
	STATICPROC(14),
	CONSTANT(15),
	STAPARAM(16),
	STRUCT(26),
	UNION(27),
	ENUM(28),
	INDIRECT(34);
	
	public static final DataType dataType = EcoffEnumConverterUtil.toDataType(EcoffSt.class);

	private final int value;

	private EcoffSt(int value) {
		this.value = value;
	}

	@Override
	public long getValue() {
		return value;
	}

	public static EcoffSt toEnum(long value) {
		if (value <= STAPARAM.value && value >= 0) {
			return values()[(int) value];
		}
		if (value == STRUCT.value) {
			return STRUCT;
		}
		if (value == UNION.value) {
			return UNION;
		}
		if (value == ENUM.value) {
			return ENUM;
		}
		if (value == INDIRECT.value) {
			return INDIRECT;
		}
		return null;
	}

}
