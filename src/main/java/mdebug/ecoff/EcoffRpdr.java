package mdebug.ecoff;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

import static ghidra.app.util.bin.StructConverter.*;

/**
 * ECOFF Relative Procedure Descriptor Record
 */
public final class EcoffRpdr {

    /** memory address of start of procedure */
    private final int addr;

    /** save register mask */
    private final int regmask;

    /** save register offset */
    private final int regoffset;

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

    /** index into the runtime string table */
    private final int irpss;

    /** pointer to exception array */
	private final int exception_info;
	
	public static final DataType dataType = getDataType();

    public EcoffRpdr(BinaryReader reader) throws IOException {
        this.addr = reader.readNextInt();
        this.regmask = reader.readNextInt();
        this.regoffset = reader.readNextInt();
        this.fregmask = reader.readNextInt();
        this.fregoffset = reader.readNextInt();
        this.frameoffset = reader.readNextInt();
        this.framereg = reader.readNextShort();
        this.pcreg = reader.readNextShort();
        this.irpss = reader.readNextInt();
        // skip the reserved field
        reader.readNextInt();
        this.exception_info = reader.readNextInt();
    }

    /**
     * @return the adr
     */
    public int getAdr() {
        return addr;
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
    public short getFrameReg() {
        return framereg;
    }

    /**
     * @return the pcreg
     */
    public short getPcReg() {
        return pcreg;
    }

    /**
     * @return the irpss
     */
    public int getIrpss() {
        return irpss;
    }

    /**
     * @return the exception_info
     */
    public int getExceptionInfo() {
        return exception_info;
    }

    private static final DataType getDataType() {
		Structure struct = new StructureDataType(EcoffHdrr.ECOFF_PATH, "RPDR", 0);
		struct.add(DWORD, "addr", "memory address of start of procedure");
		struct.add(DWORD, "regmask", "save register mask");
		struct.add(DWORD, "regoffset", "save register offset");
		struct.add(DWORD, "fregmask", "save floating point register mask");
		struct.add(DWORD, "fregoffset", "save floating point register offset");
		struct.add(DWORD, "frameoffset", "frame size");
		struct.add(WORD, "framereg", "frame pointer register");
		struct.add(WORD, "pcreg", "offset or reg of return pc");
		struct.add(DWORD, "irpss", "index into the runtime string table");
		struct.add(DWORD, "exception_info", "pointer to exception array");
		return struct;
	}
    
}
