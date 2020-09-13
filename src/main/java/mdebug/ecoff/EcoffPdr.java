package mdebug.ecoff;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.exception.AssertException;

import static ghidra.app.util.bin.StructConverter.*;

/**
 * ECOFF Procedure Descriptor Record
 */
public class EcoffPdr {

	public final static DataType BOOL = BooleanDataType.dataType;

    /** memory address of start of procedure */
    private final int addr;

    /** start of local symbol entries */
    private final int isym;

    /** start of line number entries */
    private final int iline;

    /** save register mask */
    private final int regmask;

    /** save register offset */
    private final int regoffset;

    /** start of optimization symbol entries */
    private final int iopt;

    /** save floating point register mask */
    private final int fregmask;

    /** save floating point register offset */
    private final int fregoffset;

    /** frame size */
    private final int frameoffset;

    /** frame pointer register */
    private final short framereg;

    /** offset or reg of return pc */
    private final short pcreg;

    /** lowest line in the procedure */
    private final int lnLow;

    /** highest line in the procedure */
    private final int lnHigh;

    /** byte offset for this procedure from the fd base */
	private final int cbLineOffset;

	/** byte size of GP prologue */
	private final int gpPrologue;

	/** true if the procedure uses GP */
	private final boolean gpUsed;

	/** true if register frame procedure */
	private final boolean regFrame;

	/** true if compiled with -pg */
	private final boolean prof;

	/** offset of local variables from vfp */
	private final int localOffset;

	private final boolean is64bit;

	private static final int SIZE = 52;
	private static final int SIZE64 = SIZE+4;
	private EcoffSymr symr;

	public static final DataType dataType = getDataType(false);
	public static final DataType dataType64 = getDataType(true);

	protected EcoffPdr(BinaryReader reader, boolean is64Bit) throws IOException {
		this(reader, is64Bit, Collections.emptyList());
	}

    public EcoffPdr(BinaryReader reader, boolean is64Bit, List<EcoffSymr> symrs) throws IOException {
		this.is64bit = is64Bit;
        this.addr = reader.readNextInt();
		this.isym = reader.readNextInt();
        this.iline = reader.readNextInt();
        this.regmask = reader.readNextInt();
        this.regoffset = reader.readNextInt();
        this.iopt = reader.readNextInt();
        this.fregmask = reader.readNextInt();
        this.fregoffset = reader.readNextInt();
        this.frameoffset = reader.readNextInt();
        this.framereg = reader.readNextShort();
        this.pcreg = reader.readNextShort();
        this.lnLow = reader.readNextInt();
        this.lnHigh = reader.readNextInt();
		this.cbLineOffset = reader.readNextInt();

		if (is64bit) {
			this.gpPrologue = reader.readNextByte();
			Scalar scalar = new Scalar(16, reader.readNextShort(), false);
			this.gpUsed = scalar.testBit(0);
			this.regFrame = scalar.testBit(1);
			this.prof = scalar.testBit(2);
			this.localOffset = reader.readNextUnsignedByte();
		} else {
			this.gpPrologue = 0;
			this.gpUsed = false;
			this.regFrame = false;
			this.prof = false;
			this.localOffset = 0;
		}
	}

	/**
	 * @return the symbol name
	 * @throws IOException
	 */
	public String getSymbolName() throws IOException {
		return symr != null ? symr.getSymbolName() : "";
	}

	public EcoffSymr getSymbol() {
		return symr;
	}

	@Override
	public String toString() {
		try {
			String fName = getSymbolName();
			if (fName != null && !fName.equals("")) {
				return fName;
			}
		} catch (IOException e) {
			// returning default toString
		}
		return super.toString();
	}

	void setSymbol(List<EcoffSymr> symbols) {
		if (isym > 0 && isym < symbols.size()) {
			this.symr = symbols.get(isym);
		} else {
			this.symr = null;
		}
	}

	/**
	 * Gets the ECOFF File Descriptor record for the file which
	 * contained this function or null if it's an external function.
	 *
	 * @return the EcoffFdr for this function.
	 */
	public EcoffFdr getFile() {
		if (symr != null) {
			return symr.getFile();
		}
		return null;
	}

    /**
     * @return the adr
     */
    public int getAdr() {
        return addr;
    }

    /**
     * @return the isym
     */
    public int getIsym() {
        return isym;
    }

    /**
     * @return the iline
     */
    public int getIline() {
        return iline;
    }

    /**
     * @return the regmask
     */
    public int getRegmask() {
        return regmask;
    }

    /**
     * @return the regoffset
     */
    public int getRegoffset() {
        return regoffset;
    }

    /**
     * @return the iopt
     */
    public int getIopt() {
        return iopt;
    }

    /**
     * @return the fregmask
     */
    public int getFregmask() {
        return fregmask;
    }

    /**
     * @return the fregoffset
     */
    public int getFregoffset() {
        return fregoffset;
    }

    /**
     * @return the frameoffset
     */
    public int getFrameoffset() {
        return frameoffset;
    }

    /**
     * @return the framereg
     */
    public short getFramereg() {
        return framereg;
    }

    /**
     * @return the pcreg
     */
    public short getPcreg() {
        return pcreg;
    }

    /**
     * @return the lnLow
     */
    public int getLnLow() {
        return lnLow;
    }

    /**
     * @return the lnHigh
     */
    public int getLnHigh() {
        return lnHigh;
    }

    /**
     * @return the cbLineOffset
     */
    public int getCbLineOffset() {
        return cbLineOffset;
	}

		/**
	 * @return the _gp_prologue_8
	 */
	public int get_gp_prologue_8() {
		return gpPrologue;
	}

	/**
	 * @return the _gp_used_1
	 */
	public boolean is_gp_used_1() {
		return gpUsed;
	}

	/**
	 * @return the _reg_frame_1
	 */
	public boolean is_reg_frame_1() {
		return regFrame;
	}

	/**
	 * @return the _prof_1
	 */
	public boolean is_prof_1() {
		return prof;
	}

	/**
	 * @return the _localoff_8
	 */
	public int get_localoff_8() {
		return localOffset;
	}

	private static final DataType getDataType(boolean is64Bit) {
		Structure struct = new StructureDataType(EcoffHdrr.ECOFF_PATH, "PDR", 0);
		struct.add(DWORD, "adr", "memory address of start of procedure");
		struct.add(DWORD, "isym", "start of local symbol entries");
		struct.add(DWORD, "iline", "start of line number entries");
		struct.add(DWORD, "regmask", "save register mask");
		struct.add(DWORD, "regoffset", "save register offset");
		struct.add(DWORD, "iopt", "start of optimization symbol entries");
		struct.add(DWORD, "fregmask", "save floating point register mask");
		struct.add(DWORD, "fregoffset", "save floating point register offset");
		struct.add(DWORD, "frameoffset", "frame size");
		struct.add(WORD, "framereg", "frame pointer register");
		struct.add(WORD, "pcreg", "offset or reg of return pc");
		struct.add(DWORD, "lnLow", "lowest line in the procedure");
		struct.add(DWORD, "lnHigh", "highest line in the procedure");
		struct.add(DWORD, "cbLineOffset", "byte offset for this procedure from the fd base");
		if (is64Bit) {
			try {
				struct.addBitField(BYTE, 8, "gp_prologue", "byte size of GP prologue");
				struct.addBitField(BOOL, 1, "gp_used", "true if the procedure uses GP");
				struct.addBitField(BOOL, 1, "reg_frame", "true if register frame procedure");
				struct.addBitField(BOOL, 1, "prof", "true if compiled with -pg");
				struct.addBitField(WORD, 13, "reserved", "reserved: must be zero");
				struct.addBitField(BYTE, 8, "localoff", "offset of local variables from vfp");
			} catch (InvalidDataTypeException e) {
				throw new AssertException(e);
			}
		}
		struct.setToMachineAlignment();
        return struct;
	}

	public static int getDataTypeLength(boolean is64Bit) {
		return is64Bit ? SIZE64 : SIZE;
	}

}
