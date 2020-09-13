package mdebug.ecoff;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.Language;
import ghidra.util.task.TaskMonitor;

import static ghidra.app.util.bin.StructConverter.*;

/**
 * A 0x30 byte ECOFF section header
 */
public class EcoffSectionHeader {

	// the actual name
	private final String name;

	/** physical address, aliased s_nlib */
	private final int s_paddr;

	/** virtual address */
	private final int s_vaddr;

	/** section size */
	private final int s_size;

	/** file ptr to raw data for section */
	private final int s_scnptr;

	/** file ptr to relocation */
	private final int s_relptr;

	/** file ptr to line numbers */
	private final int s_lnnoptr;

	/** number of relocation entries */
	private final short s_nreloc;

	/** number of line number entries */
	private final short s_nlnno;

	/** flags */
	private final EcoffSectionType s_flags;

	public static final DataType dataType = getDataType();

	protected List<EcoffRelocation> _relocations = new ArrayList<>();
	protected List<EcoffLineNumber> _lineNumbers = new ArrayList<>();

	public EcoffSectionHeader(BinaryReader reader, EcoffFileHdr header) throws IOException {
		name = reader.readNextAsciiString(8);
		s_paddr    = reader.readNextInt();
		s_vaddr    = reader.readNextInt();
		s_size     = reader.readNextInt();
		s_scnptr   = reader.readNextInt();
		s_relptr   = reader.readNextInt();
		s_lnnoptr  = reader.readNextInt();
		s_nreloc   = reader.readNextShort();
		s_nlnno    = reader.readNextShort();
		s_flags    = EcoffSectionType.toEnum(reader.readNextInt());
	}

	private static final DataType getDataType() {
		Structure struct = new StructureDataType(EcoffHdrr.ECOFF_PATH, "SCNHDR", 0);
		Array array = new ArrayDataType(CharDataType.dataType, 8, 1);
		struct.add(array, "s_name", "section name");
		struct.add(DWORD, "s_paddr", "physical address, aliased s_nlib");
		struct.add(DWORD, "s_vaddr", "virtual address");
		struct.add(DWORD, "s_size", "section size");
		struct.add(DWORD, "s_scnptr", "file ptr to raw data for section");
		struct.add(DWORD, "s_relptr", "file ptr to relocation");
		struct.add(DWORD, "s_lnnoptr", "file ptr to line numbers");
		struct.add(WORD, "s_nreloc", "number of relocation entries");
		struct.add(WORD, "s_nlnno", "number of line number entries");
		return struct;
	}

	/**
	 * Parse the relocations and line number information
	 * for this section.
	 * @throws IOException if an I/O error occurs
	 */
	void parse(BinaryReader reader, TaskMonitor monitor) throws IOException {
		long origIndex = reader.getPointerIndex();
		try {
			parseRelocations(reader, monitor);
			//parseLineNumbers(reader, monitor);
		}
		finally {
			reader.setPointerIndex(origIndex);
		}
	}
	
	private void parseRelocations(BinaryReader reader, TaskMonitor monitor)
			throws IOException {
		reader.setPointerIndex(s_relptr);
		for (int i = 0; i < s_nreloc; ++i) {
			if (monitor.isCancelled()) {
				break;
			}
			_relocations.add(new EcoffRelocation(reader));
		}
	}

	@Override
	public String toString() {
		return name;
	}

	/**
	 * @return the name
	 */
	public String getName() {
		return name;
	}

	public Address getPhysicalAddress(Language language) {
		return language.getDefaultSpace().getAddress(s_paddr);
	}

	/**
	 * @return the s_paddr
	 */
	public int getPhysicalAddress() {
		return s_paddr;
	}

	/**
	 * @return the s_vaddr
	 */
	public int getVaddr() {
		return s_vaddr;
	}

	/**
	 * @return the s_size
	 */
	public int getSize() {
		return s_size;
	}

	/**
	 * @return the s_scnptr
	 */
	public int getPointerToRawData() {
		return s_scnptr;
	}

	/**
	 * @return the s_relptr
	 */
	public int getRelocationPointer() {
		return s_relptr;
	}

	/**
	 * @return the s_lnnoptr
	 */
	public int getLineNumPointer() {
		return s_lnnoptr;
	}

	/**
	 * @return the s_nreloc
	 */
	public short getNumRelocations() {
		return s_nreloc;
	}

	/**
	 * @return the s_nlnno
	 */
	public short getNumLineNumbers() {
		return s_nlnno;
	}

	/**
	 * @return the s_flags
	 */
	public EcoffSectionType getFlags() {
		return s_flags;
	}

	/**
	 * @return the _relocations
	 */
	public List<EcoffRelocation> getRelocations() {
		return _relocations;
	}

	/**
	 * @return the _lineNumbers
	 */
	public List<EcoffLineNumber> getLineNumbers() {
		return _lineNumbers;
	}

	
	public boolean isUninitializedData() {
		switch(s_flags) {
			case STYP_BSS:
			case STYP_SBSS:
			case STYP_SDATA:
				return true;
			default:
				return false;
		}
	}

	public boolean isInitializedData() {
		switch(s_flags) {
			case STYP_DATA:
			case STYP_LIT4:
			case STYP_LIT8:
			case STYP_RDATA:
			case STYP_RCONST:
				return true;
			default:
				return false;
		}
	}

	public boolean isData() {
		return isInitializedData() || isUninitializedData();
	}

	public boolean isReadable() {
		// got lazy
		return true;
	}

	public boolean isGroup() {
		return s_flags.equals(EcoffSectionType.STYP_GROUP);
	}

	public boolean isWritable() {
		return s_flags.equals(EcoffSectionType.STYP_TEXT);
	}

	public boolean isExecutable() {
		return s_flags.equals(EcoffSectionType.STYP_TEXT);
	}

	public boolean isAllocated() {
		return (!s_flags.equals(EcoffSectionType.STYP_COPY) &&
		!s_flags.equals(EcoffSectionType.STYP_PAD) &&
		!s_flags.equals(EcoffSectionType.STYP_DSECT));
	}

}
