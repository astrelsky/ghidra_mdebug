package mdebug.ecoff;

import ghidra.program.model.data.DataType;

/*
 * ECOFF SYMR Storage Classes
 */
public enum EcoffSc implements EcoffEnumConverter {

    NIL(0),

    /** text symbol */
    TEXT(1),

    /** initialized data symbol */
    DATA(2),

    /** un-initialized data symbol */
    BSS(3),

    /** value of symbol is register number */
    REGISTER(4),

    /** value of symbol is absolute */
    ABS(5),

    /** value is undefined */
    UNDEFINED(6),

    /** variable's value is IN se->va.?? */
    CDBLOCAL(7),

    /** this is a bit field */
    BITS(8),

    /** variable's value is IN CDB's address space */
    CDBSYSTEM(9),

    /** register value saved on stack */
    REGIMAGE(10),

    /** symbol contains debugger information */
    INFO(11),

    /** address in struct user for current process */
    USERSTRUCT(12),

    /** load time only small data */
    SDATA(13),

    /** load time only small common */
    SBSS(14),

    /** load time only read only data */
    RDATA(15),

    /** Var parameter (fortran,pascal) */
    VAR(16),

    /** common variable */
    COMMON(17),

    /** small common */
    SCOMMON(18),

    /** Var parameter in a register */
    VARREGISTER(19),

    /** Variant record */
    VARIANT(20),

    /** small undefined(external) data */
    SUNDEFINED(21),

    /** .init section symbol */
    INIT(22),

    /** Fortran or PL/1 ptr based var */
    BASEDVAR(23),

    /** exception handling data */
    XDATA(24),

    /** Procedure section */
    PDATA(25),

    /** .fini section */
    FINI(26),

    /** .rconst section */
    RCONST(27),

	MAX(32);
	
	public static final DataType dataType = EcoffEnumConverterUtil.toDataType(EcoffSc.class);

    private final int value;

    private EcoffSc(int value) {
        this.value = value;
    }

    @Override
    public long getValue() {
        return (long) value;
    }

    public static EcoffSc toEnum(long value) {
        if (value <= RCONST.value && value > 0) {
            return values()[(int) value];
        }
        if (value == MAX.value) {
            return MAX;
        }
        return null;
    }
}
