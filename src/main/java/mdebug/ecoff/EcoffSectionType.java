package mdebug.ecoff;

import ghidra.program.model.data.DataType;

public enum EcoffSectionType implements EcoffEnumConverter {
	STYP_REG (0x00),
	STYP_DSECT (0x01),
	STYP_NOLOAD (0x02),
	STYP_GROUP (0x04),
	STYP_PAD (0x08),
	STYP_COPY (0x10),
	STYP_TEXT (0x20),		/* section contains text only */
	STYP_DATA (0x40),		/* section contains data only */
	STYP_BSS (0x80),	/* section contains bss only */

	S_NEWFCN (0x10),

	S_SHRSEG (0x20),
	/** Overlay section (defines a piece of another named section which has no bytes) */
	STYP_OVER(0x0400),
	/** Library section */
	STYP_LIB(0x0800),
	STYP_LOADER(0x1000),
	/** Debug section */
	STYP_DEBUG(0x2000),
	/** Type check section */
	STYP_TYPECHK(0x4000),
	/** RLD and line number overflow sec hdr section */
	STYP_OVRFLO(0x8000),

	/* ECOFF uses some additional section flags.  */
	STYP_RDATA(0x100),
	STYP_SDATA(0x200),
	STYP_SBSS(0x400),
	STYP_GOT(0x1000),
	STYP_DYNAMIC(0x2000),
	STYP_DYNSYM(0x4000),
	STYP_RELDYN(0x8000),
	STYP_DYNSTR(0x10000),
	STYP_HASH(0x20000),
	STYP_LIBLIST(0x40000),
	STYP_CONFLIC(0x100000),
	STYP_ECOFF_FINI(0x1000000),
	STYP_EXTENDESC(0x2000000), /* 0x02FFF000 bits => scn type, rest clr */
	STYP_LITA(0x4000000),
	STYP_LIT8(0x8000000),
	STYP_LIT4(0x10000000),
	STYP_ECOFF_LIB(0x40000000),
	STYP_ECOFF_INIT(0x80000000),
	STYP_OTHER_LOAD (0x81000000),

	/* extended section types */
	STYP_COMMENT(0x2100000),
	STYP_RCONST(0x2200000),
	STYP_XDATA(0x2400000),
	STYP_PDATA(0x2800000),
	STYP_UNKNOWN(0xFFFFFFFF);
	
	public static final DataType dataType =
		EcoffEnumConverterUtil.toDataType(EcoffSectionType.class);

	private final int value;

	private EcoffSectionType(int value) {
		this.value = value;
	}

	@Override
	public long getValue() {
		return value;
	}

	public static EcoffSectionType toEnum(long value) {
		for (EcoffSectionType type : values()) {
			if (type.value == value) {
				return type;
			}
		}
		return STYP_UNKNOWN;
	}
}
