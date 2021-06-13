package mdebug.ecoff;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ghidra.app.util.bin.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import static ghidra.app.util.bin.StructConverter.*;

// hdrr = mdebug.ecoff.EcoffHdrr.getHdrr(currentProgram)

/**
 * ECOFF Symbolic Header
 */
public final class EcoffHdrr {

	public static final short MAGIC = 0x7009;

	/** 0x7009 */
	private final short magic;

	/** version stamp */
	private final short vstamp;

	/** number of line number entries */
	private final int ilineMax;

	// line numbers are compressed!
	/** number of bytes for line number entries */
	private final int cbLine;

	/** offset to start of line number entries */
	final int cbLineOffset;

	/** max index into dense number table */
	private final int idnMax;

	/** offset to start dense number table */
	private final int cbDnOffset;

	/** number of procedures */
	private final int ipdMax;

	/** offset to procedure descriptor table */
	final int cbPdOffset;

	/** number of local symbols */
	private final int isymMax;

	/** offset to start of local symbols */
	final int cbSymOffset;

	/** max index into optimization symbol entries */
	private final int ioptMax;

	/** offset to optimization symbol entries */
	private final int cbOptOffset;

	/** number of auxillary symbol entries */
	private final int iauxMax;

	/** offset to start of auxillary symbol entries */
	private final int cbAuxOffset;

	/** max index into local strings */
	private final int issMax;

	/** offset to start of local strings */
	final int cbSsOffset;

	/** max index into external strings */
	private final int issExtMax;

	/** offset to start of external strings */
	final int cbSsExtOffset;

	/** number of file descriptor entries */
	private final int ifdMax;

	/** offset to file descriptor table */
	private final int cbFdOffset;

	/** number of relative file descriptor entries */
	private final int crfd;

	/** offset to relative file descriptor table */
	private final int cbRfdOffset;

	/** max index into external symbols */
	private final int iextMax;

	/** offset to start of external symbol entries */
	private final int cbExtOffset;

	protected final BinaryReader reader;
	protected final EcoffStringTable _sTable;
	private final EcoffStringTable _extSTable;

	// needed for pdr
	protected final boolean is64Bit;

	private final ArrayList<EcoffAuxu> __auxes = new ArrayList<>();
	private final ArrayList<EcoffFdr> _files = new ArrayList<>();
	private final ArrayList<EcoffSymr> _symbols = new ArrayList<>();
	private final ArrayList<EcoffPdr> _procedures = new ArrayList<>();

	protected static final CategoryPath ECOFF_PATH = new CategoryPath(CategoryPath.ROOT, "ECOFF");

	public static final DataType dataType = getDataType(false);
	public static final DataType dataType64 = getDataType(true);

	private final FileOffsetAddressFinder finder;
	private final Address address;

	// caller should expect the reader index to be incremented
	public EcoffHdrr(BinaryReader reader, FileOffsetAddressFinder finder, Address addr)
		throws IOException {
			this.address = addr;
			this.finder = finder;
			this.is64Bit = finder.getProgram().getDefaultPointerSize() > 4;
			this.reader = reader;
			this.magic = reader.readNextShort();
			this.vstamp = reader.readNextShort();
			this.ilineMax = reader.readNextInt();
			this.cbLine = reader.readNextInt();
			this.cbLineOffset = reader.readNextInt();
			this.idnMax = reader.readNextInt();
			this.cbDnOffset = reader.readNextInt();
			this.ipdMax = reader.readNextInt();
			this.cbPdOffset = reader.readNextInt();
			this.isymMax = reader.readNextInt();
			this.cbSymOffset = reader.readNextInt();
			this.ioptMax = reader.readNextInt();
			this.cbOptOffset = reader.readNextInt();
			this.iauxMax = reader.readNextInt();
			this.cbAuxOffset = reader.readNextInt();
			this.issMax = reader.readNextInt();
			this.cbSsOffset = reader.readNextInt();
			this.issExtMax = reader.readNextInt();
			this.cbSsExtOffset = reader.readNextInt();
			this.ifdMax = reader.readNextInt();
			this.cbFdOffset = reader.readNextInt();
			this.crfd = reader.readNextInt();
			this.cbRfdOffset = reader.readNextInt();
			this.iextMax = reader.readNextInt();
			this.cbExtOffset = reader.readNextInt();
			this._sTable = new EcoffStringTable(getReaderAt(cbSsOffset));
			this._extSTable = new EcoffStringTable(getReaderAt(cbSsExtOffset));
	}

	public static EcoffHdrr getHdrr(Program program) throws Exception {
		Memory mem = program.getMemory();
		MemoryBlock block = mem.getBlock(".mdebug");
		Address baseAddr = block.getStart();
		MemoryByteProvider provider = new MemoryByteProvider(mem, baseAddr);
		BinaryReader reader = new BinaryReader(provider, !mem.isBigEndian());
		if (baseAddr == null || !EcoffHdrr.isValid(reader)) {
			// not valid .mdebug section
			return null;
		}
		FileOffsetAddressFinder finder = new FileOffsetAddressFinder(mem);
		return new EcoffHdrr(reader, finder, block.getStart());
	}

	private BinaryReader getReaderAt(long offset) {
		Memory mem = finder.getMemory();
		Address addr = finder.findAddress(offset);
		MemoryByteProvider provider = new MemoryByteProvider(mem, addr);
		return new BinaryReader(provider, !mem.isBigEndian());
	}

	public Address getAddress() {
		return address;
	}

	public void parse(TaskMonitor monitor) throws CancelledException, IOException {
		fillSymrTable(monitor);
		fillPdrTable(monitor);
		fillAuxuTable(monitor);
		fillFdrTable(monitor);
	}

	/**
	 * Gets the section relative offset of the Dense Number Record Table
	 * @return the section relative offset
	 */
	public Address getDnrTableAddress() {
		if (cbDnOffset == 0) {
			return Address.NO_ADDRESS;
		}
		return finder.findAddress(cbDnOffset);
	}

	/**
	 * Gets the section relative offset of the Compressed Line Number Table
	 * @return the section relative offset
	 */
	public Address getLineNumTableAddress() {
		if (cbLineOffset == 0) {
			return Address.NO_ADDRESS;
		}
		return finder.findAddress(cbLineOffset);
	}

	public int[] getLineNumTable() throws IOException {
		// TODO the table is compressed
		return new int[0];
		/*
		if (ilineMax == 0 || ilineMax*BinaryReader.SIZEOF_INT != cbLine) {
			return new int[0];
		}
		int[] lines = new int[ilineMax];
		_reader.setPointerIndex(cbLineOffset);
		for (int i = 0; i < ilineMax; i++) {
			lines[i] = _reader.readNextInt();
		}
		return lines;
		*/
	}

	public List<EcoffDnr> getDnrTable() throws IOException {
		if (idnMax == 0) {
			return Collections.emptyList();
		}
		List<EcoffDnr> dnrs = new ArrayList<>(idnMax);
		reader.setPointerIndex(cbDnOffset);
		for (int i = 0; i < idnMax; i++) {
			dnrs.add(new EcoffDnr(reader));
		}
		return dnrs;
	}

	/**
	 * Gets the section relative offset of the Procedure Descriptor Record Table
	 * @return the section relative offset
	 */
	public Address getPdrTableAddress() {
		if (ipdMax == 0) {
			return Address.NO_ADDRESS;
		}
		return finder.findAddress(cbPdOffset);
	}

	public void fillPdrTable(TaskMonitor monitor) throws IOException, CancelledException {
		if (ipdMax > 0 && _procedures.isEmpty()) {
			_procedures.ensureCapacity(ipdMax);
			monitor.initialize(ipdMax);
			monitor.setMessage("Parsing Procedure Descriptor Records");
			BinaryReader reader = getReaderAt(cbPdOffset);
			for (int i = 0; i < ipdMax; i++) {
				monitor.checkCanceled();
				_procedures.add(new EcoffPdr(reader, is64Bit));
				monitor.incrementProgress(1);
			}
		}
	}

	public void fillAuxuTable(TaskMonitor monitor) throws IOException, CancelledException {
		if (iauxMax > 0 && __auxes.isEmpty()) {
			__auxes.ensureCapacity(iauxMax);
			monitor.initialize(iauxMax);
			monitor.setMessage("Parsing Auxillary Information");
			BinaryReader reader = getReaderAt(cbAuxOffset);
			for (int i = 0; i < iauxMax; i++) {
				monitor.checkCanceled();
				__auxes.add(new EcoffAuxu(reader));
				monitor.incrementProgress(1);
			}
		}
	}

	/**
	 * Gets the section relative offset of the Local Symbol Record Table
	 * @return the section relative offset
	 */
	public Address getSymrTableAddress() {
		if (isymMax == 0) {
			return Address.NO_ADDRESS;
		}
		return finder.findAddress(cbSymOffset);
	}

	public List<EcoffSymr> getSymbols() {
		return Collections.unmodifiableList(_symbols);
	}

	public List<EcoffAuxu> getAuxillary() {
		return Collections.unmodifiableList(__auxes);
	}

	public List<EcoffPdr> getProcedures() {
		return Collections.unmodifiableList(_procedures);
	}

	public List<EcoffFdr> getFiles() {
		return Collections.unmodifiableList(_files);
	}

	private void fillSymrTable(TaskMonitor monitor) throws IOException, CancelledException {
		if (isymMax > 0 && _symbols.isEmpty()) {
			_symbols.ensureCapacity(isymMax);
			monitor.initialize(isymMax);
			monitor.setMessage("Parsing Local Symbol Records");
			BinaryReader reader = getReaderAt(cbSymOffset);
			for (int i = 0; i < isymMax; i++) {
				monitor.checkCanceled();
				_symbols.add(new EcoffSymr(reader));
				monitor.incrementProgress(1);
			}
		}
	}

	/**
	 * Gets the section relative offset of the Optimization Record Table
	 * @return the section relative offset
	 */
	public Address getOptrTableAddress() {
		if (ioptMax == 0) {
			return Address.NO_ADDRESS;
		}
		return finder.findAddress(cbOptOffset);
	}

	public List<EcoffOptr> getOptrTable() throws IOException {
		if (ioptMax == 0) {
			return Collections.emptyList();
		}
		List<EcoffOptr> optrs = new ArrayList<>(ioptMax);
		reader.setPointerIndex(cbOptOffset);
		for (int i = 0; i < ioptMax; i++) {
			optrs.add(new EcoffOptr(reader));
		}
		return optrs;
	}

	/**
	 * Gets the section relative offset of the Auxillary Table
	 * @return the section relative offset
	 */
	public Address getAuxTableAddress() {
		if (iauxMax == 0) {
			return Address.NO_ADDRESS;
		}
		return finder.findAddress(cbAuxOffset);
	}

	/**
	 * Gets the section relative offset of the File Descriptor Record Table
	 * @return the section relative offset
	 */
	public Address getFdrTableAddress() {
		if (ifdMax == 0) {
			return Address.NO_ADDRESS;
		}
		return finder.findAddress(cbFdOffset);
	}

	private void fillFdrTable(TaskMonitor monitor) throws IOException, CancelledException {
		if (ifdMax > 0 && _files.isEmpty()) {
			_files.ensureCapacity(ifdMax);
			monitor.initialize(ifdMax);
			monitor.setMessage("Parsing File Descriptor Records");
			BinaryReader reader = getReaderAt(cbFdOffset);
			for (int i = 0; i < ifdMax; i++) {
				monitor.checkCanceled();
				_files.add(new EcoffFdr(this, reader));
				monitor.incrementProgress(1);
			}
		}
	}

	/**
	 * Gets the section relative offset of the External Symbol Record Table
	 * @return the section relative offset
	 */
	public Address getExtrTableAddress() {
		if (iextMax == 0) {
			return Address.NO_ADDRESS;
		}
		return finder.findAddress(cbExtOffset);
	}

	public List<EcoffExtr> getExtrTable() throws IOException {
		if (iextMax == 0) {
			return Collections.emptyList();
		}
		List<EcoffExtr> extrs = new ArrayList<>(iextMax);
		reader.setPointerIndex(cbExtOffset);
		for (int i = 0; i < iextMax; i++) {
			extrs.add(new EcoffExtr(reader, _extSTable));
		}
		return extrs;
	}

	/**
	 * Gets the section relative offset of the Relative File Descriptor Table
	 * @return the section relative offset
	 */
	public Address getRfdTableAddress() {
		if (crfd == 0) {
			return Address.NO_ADDRESS;
		}
		return finder.findAddress(cbRfdOffset);
	}

	/**
	 * Gets the section relative offset of the Local String Table
	 * @return the section relative offset
	 */
	public Address getStringTableAddress() {
		if (issMax == 0) {
			return Address.NO_ADDRESS;
		}
		return finder.findAddress(cbSsOffset);
	}

	/**
	 * Gets the section relative offset of the External String Table
	 * @return the section relative offset
	 */
	public Address getExtStringTableAddress() {
		if (issExtMax == 0) {
			return Address.NO_ADDRESS;
		}
		return finder.findAddress(cbSsExtOffset);
	}

	/**
	 * Checks if the bytes at the start of the reader may be a valid
	 * ECOFF HDRR
	 * @param reader
	 * @return true if a valid ECOFF HDRR
	 * @throws IOException if an IOException occurs reading the data
	 */
	public static boolean isValid(BinaryReader reader) throws IOException {
		return reader.peekNextShort() == MAGIC;
	}

	/**
	 * @return the magic
	 */
	public short getMagic() {
		return magic;
	}

	/**
	 * @return the version stamp
	 */
	public short getVstamp() {
		return vstamp;
	}

	/**
	 * @return the max number of lines (uncompressed)
	 */
	public int getIlineMax() {
		return ilineMax;
	}

	/**
	 * @return the number of compressed bytes in the line table
	 */
	public int getCbLine() {
		return cbLine;
	}

	/**
	 * @return the total number of Dense Number Records
	 */
	public int getIdnMax() {
		return idnMax;
	}

	/**
	 * @return the total number of Procedure Descriptor Records
	 */
	public int getIpdMax() {
		return ipdMax;
	}

	/**
	 * @return the total number of Local Symbol Records
	 */
	public int getIsymMax() {
		return isymMax;
	}

	/**
	 * @return the total number of Optimization Records
	 */
	public int getIoptMax() {
		return ioptMax;
	}

	/**
	 * @return the total number of Auxillary Records
	 */
	public int getIauxMax() {
		return iauxMax;
	}

	/**
	 * @return the length of the string table in bytes.
	 */
	public int getIssMax() {
		return issMax;
	}

	/**
	 * @return the length of the external string table in bytes.
	 */
	public int getIssExtMax() {
		return issExtMax;
	}

	/**
	 * @return the total number of File Descriptor Records
	 */
	public int getIfdMax() {
		return ifdMax;
	}

	/**
	 * @return the total number of Relative File Descriptor Records
	 */
	public int getCrfd() {
		return crfd;
	}

	/**
	 * @return the total number of External Symbol Records
	 */
	public int getIextMax() {
		return iextMax;
	}

	FileOffsetAddressFinder getAddressFinder() {
		return finder;
	}

	public static DataType getDataType(boolean is64Bit) {
		Structure struct = new StructureDataType(ECOFF_PATH, "HDRR", 0);
		struct.add(WORD, "magic", "0x7009");
		struct.add(WORD, "vstamp", "version stamp");
		struct.add(DWORD, "ilineMax", "number of line number entries");

		// line numbers are compressed!
		struct.add(DWORD, "cbLine", "number of bytes for line number entries");
		struct.add(DWORD, "cbLineOffset", "offset to start of line number entries");
		struct.add(DWORD, "idnMax", "max index into dense number table");
		struct.add(DWORD, "cbDnOffset", "offset to start dense number table");
		struct.add(DWORD, "ipdMax", "number of procedures");
		struct.add(DWORD, "cbPdOffset", "offset to procedure descriptor table");
		struct.add(DWORD, "isymMax", "number of local symbols");
		struct.add(DWORD, "cbSymOffset", "offset to start of local symbols");
		struct.add(DWORD, "ioptMax", "max index into optimization symbol entries");
		struct.add(DWORD, "cbOptOffset", "offset to optimization symbol entries");
		struct.add(DWORD, "iauxMax", "number of auxillary symbol entries");
		struct.add(DWORD, "cbAuxOffset", "offset to start of auxillary symbol entries");
		struct.add(DWORD, "issMax", "max index into local strings");
		struct.add(DWORD, "cbSsOffset", "offset to start of local strings");
		struct.add(DWORD, "issExtMax", "max index into external strings");
		struct.add(DWORD, "cbSsExtOffset", "offset to start of external strings");
		struct.add(DWORD, "ifdMax", "number of file descriptor entries");
		struct.add(DWORD, "cbFdOffset", "offset to file descriptor table");
		struct.add(DWORD, "crfd", "number of relative file descriptor entries");
		struct.add(DWORD, "cbRfdOffset", "offset to relative file descriptor table");
		struct.add(DWORD, "iextMax", "max index into external symbols");
		struct.add(DWORD, "cbExtOffset", "offset to start of external symbol entries");
		return struct;
	}

	public DataType toDataType() {
		return getDataType(is64Bit);
	}

	public boolean is64Bit() {
		return is64Bit;
	}
}
