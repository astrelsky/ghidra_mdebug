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
 * ECOFF File Descriptor Record
 */
public class EcoffFdr {

	/** memory address of beginning of file */
	private final int adr;

	/** file name (of source, if known) */
	private final int rss;

	/** file's string space */
	private final int issBase;

	/** number of bytes in the ss */
	private final int cbSs;

	/** beginning of symbols */
	private final int isymBase;

	/** count file's of symbols */
	private final int csym;

	/** file's line symbols */
	private final int ilineBase;

	/** count of file's line symbols */
	private final int cline;

	/** file's optimization entries */
	private final int ioptBase;

	/** count of file's optimization entries */
	private final int copt;

	/** start of procedures for this file */
	private final short ipdFirst;

	/** count of procedures for this file */
	private final short cpd;

	/** file's auxiliary entries */
	private final int iauxBase;

	/** count of file's auxiliary entries */
	private final int caux;

	/** index into the file indirect table */
	private final int rfdBase;

	/** count file indirect entries */
	private final int crfd;

	/** language for this file */
	private final EcoffLanguageCode lang_5;

	/** whether this file can be merged */
	private final boolean fMerge_1;

	/** true if it was read in (not just created) */
	private final boolean fReadin_1;

	// I changed this one for clarity
	/** true if AUXU's are big endian */
	private final boolean fBigEndian_1;

	/** level this file was compiled with */
	private final byte glevel_2;

	/** byte offset from header for this file ln's */
	private final int cbLineOffset;

	/** size of lines for this file */
	private final int cbLine;

	private final BinaryReader reader;
	private final EcoffHdrr hdrr;

	public final List<EcoffSymr> symbols;
	public final List<EcoffPdr> procedures;
	public final List<EcoffAuxu> auxes;

	public static final DataType dataType = getDataType();

	EcoffFdr(EcoffHdrr hdrr, BinaryReader reader) throws IOException {
		this.hdrr = hdrr;
		this.adr = reader.readNextInt();
		this.rss = reader.readNextInt();
		this.issBase = reader.readNextInt();
		this.cbSs = reader.readNextInt();
		this.isymBase = reader.readNextInt();
		this.csym = reader.readNextInt();
		this.ilineBase = reader.readNextInt();
		this.cline = reader.readNextInt();
		this.ioptBase = reader.readNextInt();
		this.copt = reader.readNextInt();
		this.ipdFirst = reader.readNextShort();
		this.cpd = reader.readNextShort();
		this.iauxBase = reader.readNextInt();
		this.caux = reader.readNextInt();
		this.rfdBase = reader.readNextInt();
		this.crfd = reader.readNextInt();
		int i = reader.readNextInt();
		Scalar scalar = new Scalar(5, i, false);
		this.lang_5 = EcoffLanguageCode.toEnum((byte) scalar.getValue());
		scalar = new Scalar(DWORD.getLength() << 3, i, false);
		this.fMerge_1 = scalar.testBit(6);
		this.fReadin_1 = scalar.testBit(7);
		this.fBigEndian_1 = scalar.testBit(8);
		this.glevel_2 = (byte) ((i >> 8) & 3); // bits 9 & 10
		this.cbLineOffset = reader.readNextInt();
		this.cbLine = reader.readNextInt();
		this.reader = reader;
		this.symbols = doGetSymrTable();
		this.procedures = doGetPdrTable();
		this.auxes = doGetAuxTable();
	}

	private List<EcoffSymr> doGetSymrTable() throws IOException {
		if (csym > 0) {
			List<EcoffSymr> symrs = hdrr.getSymbols().subList(isymBase, isymBase+csym);
			symrs.forEach((a)->a.setFile(this));
			return symrs;
		}
		return Collections.emptyList();
	}

	public int[] getLineTable() throws IOException {
		if (cline == 0) {
			return new int[0];
		}
		int[] lines = new int[cline];
		reader.setPointerIndex(hdrr.cbLineOffset + ilineBase*BinaryReader.SIZEOF_INT);
		for (int i = 0; i < cline; i++) {
			lines[i] = reader.readNextInt();
		}
		return lines;
	}

	private List<EcoffPdr> doGetPdrTable() {
		if (cpd == 0) {
			return Collections.emptyList();
		}
		final int ipdStart = ((int) ipdFirst) & 0xffff;
		List<EcoffPdr> pdrs = hdrr.getProcedures().subList(ipdStart, ipdStart+cpd);
		pdrs.forEach((a)->a.setSymbol(symbols));
		return pdrs;
	}

	private List<EcoffAuxu> doGetAuxTable() {
		if (caux == 0) {
			return Collections.emptyList();
		}
		return hdrr.getAuxillary().subList(iauxBase, iauxBase+caux);
	}

	/**
	 * @return the adr
	 */
	public int getAdr() {
		return adr;
	}

	/**
	 * @return the filename
	 * @throws IOException
	 */
	public String getFileName() throws IOException {
		return hdrr._sTable.getString(rss);
	}

	@Override
	public String toString() {
		try {
			String fName = getFileName();
			if (fName != null && !fName.isBlank()) {
				return fName;
			}
		} catch (IOException e) {
			// returning default toString
		}
		return super.toString();
	}

	EcoffSymr getSymbol(int index) {
		if (index > 0 && index < symbols.size()) {
			return symbols.get(index);
		}
		return null;
	}

	String getSymbolName(int index) throws IOException {
		return hdrr._sTable.getString(index+issBase);
	}

	EcoffAuxu getAuxu(int index) {
		if (index > 0 && index < auxes.size()) {
			return auxes.get(index);
		}
		return null;
	}

	/**
	 * @return the issBase
	 */
	public int getIssBase() {
		return issBase;
	}

	/**
	 * @return the cbSs
	 */
	public int getCbSs() {
		return cbSs;
	}

	/**
	 * @return the isymBase
	 */
	public int getIsymBase() {
		return isymBase;
	}

	/**
	 * @return the csym
	 */
	public int getCsym() {
		return csym;
	}

	/**
	 * @return the ilineBase
	 */
	public int getIlineBase() {
		return ilineBase;
	}

	/**
	 * @return the cline
	 */
	public int getCline() {
		return cline;
	}

	/**
	 * @return the ioptBase
	 */
	public int getIoptBase() {
		return ioptBase;
	}

	/**
	 * @return the copt
	 */
	public int getCopt() {
		return copt;
	}

	/**
	 * @return the ipdFirst
	 */
	public short getIpdFirst() {
		return ipdFirst;
	}

	/**
	 * @return the cpd
	 */
	public short getCpd() {
		return cpd;
	}

	/**
	 * @return the iauxBase
	 */
	public int getIauxBase() {
		return iauxBase;
	}

	/**
	 * @return the caux
	 */
	public int getCaux() {
		return caux;
	}

	/**
	 * @return the rfdBase
	 */
	public int getRfdBase() {
		return rfdBase;
	}

	/**
	 * @return the crfd
	 */
	public int getCrfd() {
		return crfd;
	}

	/**
	 * @return the lang
	 */
	public EcoffLanguageCode getLang() {
		return lang_5;
	}

	/**
	 * @return the fMerge
	 */
	public boolean isFMerge() {
		return fMerge_1;
	}

	/**
	 * @return the fReadin
	 */
	public boolean isFReadin() {
		return fReadin_1;
	}

	/**
	 * @return the fBigEndian
	 */
	public boolean isFBigEndian() {
		return fBigEndian_1;
	}

	/**
	 * @return the glevel
	 */
	public byte getGlevel() {
		return glevel_2;
	}

	/**
	 * @return the cbLineOffset
	 */
	public int getCbLineOffset() {
		return cbLineOffset;
	}

	/**
	 * @return the cbLine
	 */
	public int getCbLine() {
		return cbLine;
	}

	public static final DataType getDataType() {
		try {
			Structure struct = new StructureDataType(EcoffHdrr.ECOFF_PATH, "FDR", 0);
			struct.add(DWORD, "adr", " memory address of beginning of file ");
			struct.add(DWORD, "rss", " file name (of source, if known) ");
			struct.add(DWORD, "issBase", " file's string space ");
			struct.add(DWORD, "cbSs", " number of bytes in the ss ");
			struct.add(DWORD, "isymBase", " beginning of symbols ");
			struct.add(DWORD, "csym", " count file's of symbols ");
			struct.add(DWORD, "ilineBase", " file's line symbols ");
			struct.add(DWORD, "cline", " count of file's line symbols ");
			struct.add(DWORD, "ioptBase", " file's optimization entries ");
			struct.add(DWORD, "copt", " count of file's optimization entries ");
			struct.add(WORD, "ipdFirst", " start of procedures for this file ");
			struct.add(WORD, "cpd", " count of procedures for this file ");
			struct.add(DWORD, "iauxBase", " file's auxiliary entries ");
			struct.add(DWORD, "caux", " count of file's auxiliary entries ");
			struct.add(DWORD, "rfdBase", " index DWORDo the file indirect table ");
			struct.add(DWORD, "crfd", " count file indirect entries ");
			struct.addBitField(EcoffLanguageCode.dataType, 5, "lang", " language for this file ");
			struct.addBitField(
				BooleanDataType.dataType, 1, "fMerge", " whether this file can be merged ");
			struct.addBitField(BooleanDataType.dataType, 1,
							   "fReadin", " true if it was read in (not just created) ");
			struct.addBitField(BooleanDataType.dataType, 1,
							   "fBigEndian", " true if AUXU's are big endian ");
			struct.addBitField(BYTE, 2, "glevel", " level this file was compiled with ");
			struct.addBitField(DWORD, 22, "reserved", "reserved for future use");
			struct.add(DWORD, "cbLineOffset", " byte offset from header for this file ln's ");
			struct.add(DWORD, "cbLine", " size of lines for this file ");
			struct.setToMachineAlignment();
			return struct;
		} catch (InvalidDataTypeException e) {
			throw new AssertException(e);
		}
	}
}
