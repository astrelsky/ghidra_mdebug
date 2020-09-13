package mdebug.ecoff;

import ghidra.program.model.data.DataType;

public enum EcoffLanguageCode implements EcoffEnumConverter {
	
	C((byte) 0),
	PASCAL((byte) 1),
	FORTRAN((byte) 2),
	ASM((byte) 3),
	MACHINE((byte) 4),
	NIL((byte) 5), 
	ADA((byte) 6),
	PL1((byte) 7),
	COBOL((byte) 8),
	STDC((byte) 9),
	CPLUSPLUSV2((byte) 10),
	MAX((byte) 11);

	private final byte value;
	public static final DataType dataType = EcoffEnumConverterUtil.toDataType(EcoffLanguageCode.class);

	EcoffLanguageCode(byte value) {
		this.value = value;
	}

	@Override
	public long getValue() {
		return value;
	}

	public static EcoffLanguageCode toEnum(byte value) {
		if (value < MAX.value && value >= 0) {
			return values()[value];
		}
		return null;
	}
}
