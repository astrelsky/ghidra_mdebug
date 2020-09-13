package mdebug.ecoff;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.RandomAccessByteProvider;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import static ghidra.app.util.bin.StructConverter.*;

// fhdr = mdebug.ecoff.EcoffFileHdr.getFileHdr(currentProgram)

public class EcoffFileHdr {

	/** magic number */
	private final short f_magic;

	/** number of sections */
	private final short f_nscns;

	/** time and date stamp */
	private final int f_timdat;

	/** file pointer to symbol table */
	private final int f_symptr;

	/** number of entries in symbol table */
	private final int f_nsyms;

	/** size of optional header */
	private final short f_opthdr;

	/** flags */
	private final short f_flags;

	private EcoffMIPSAoutHeader aoutHeader;
	private List<EcoffSectionHeader> sections = new ArrayList<>();
	private List<EcoffSymr> symbols = new ArrayList<>();

	private final BinaryReader reader;

	public static final DataType dataType = getDataType();

	public EcoffFileHdr(ByteProvider provider, boolean isLittleEndian) throws IOException {
		reader = new BinaryReader(provider, isLittleEndian);

		f_magic = reader.readNextShort();
		f_nscns = reader.readNextShort();
		f_timdat = reader.readNextInt();
		f_symptr = reader.readNextInt();
		f_nsyms = reader.readNextInt();
		f_opthdr = reader.readNextShort();
		f_flags = reader.readNextShort();
	}

	public static EcoffFileHdr getFileHdr(Program program) throws Exception {
		final File file = new File(program.getExecutablePath());
		final ByteProvider provider = new RandomAccessByteProvider(file);
		return new EcoffFileHdr(provider, !program.getLanguage().isBigEndian());
	}

	public List<EcoffSectionHeader> getSections() {
		return sections;
	}

	public List<EcoffSymr> getEcoffSymbols() {
		return symbols;
	}

	private static DataType getDataType() {
		Structure struct = new StructureDataType(EcoffHdrr.ECOFF_PATH, "FILHDR", 0);
		struct.add(WORD, "f_magic", " magic number");
		struct.add(WORD, "f_nscns", " number of sections");
		struct.add(DWORD, "f_timdat", " time and date stamp");
		struct.add(DWORD, "f_symptr", " file pointer to symbol table");
		struct.add(DWORD, "f_nsyms", " number of entries in symbol table");
		struct.add(WORD, "f_opthdr", " size of optional header");
		struct.add(WORD, "f_flags", " flags");
		return struct;
	}

	public void parse(TaskMonitor monitor) throws IOException {

		monitor.setMessage("Completing file header parsing...");
		long originalIndex = reader.getPointerIndex();
		try {
			reader.setPointerIndex(dataType.getLength());
			aoutHeader = new EcoffMIPSAoutHeader(reader);

			reader.setPointerIndex(dataType.getLength() + f_opthdr);
			for (int i = 0; i < f_nscns; ++i) {
				EcoffSectionHeader section =
					new EcoffSectionHeader(reader, this);
				sections.add(section);
				section.parse(reader, monitor);
			}
			reader.setPointerIndex(f_symptr);
			//for (int i = 0; i < getSymbolTableEntries(); ++i) {
			//	EcoffSymr symbol = new EcoffSymr(_reader, this);
			//	_symbols.add(symbol);
				//i += symbol.getAuxiliaryCount();
			//}
		}
		finally {
			reader.setPointerIndex(originalIndex);
		}
	}

	/**
	 * Returns the a.out optional header.
	 * This return value may be null.
	 * @return the a.out optional header
	 */
	public EcoffMIPSAoutHeader getOptionalHeader() {
		return aoutHeader;
	}

	public long getImageBase() {
		for (EcoffSectionHeader section : sections) {
			if (section.getFlags().equals(EcoffSectionType.STYP_TEXT)) {
				return section.getPhysicalAddress() - section.getPointerToRawData();
			}
		}
		return 0;
	}

	public int getOptionalHeaderSize() {
		return f_opthdr;
	}

	/**
	 * @return the f_magic
	 */
	public short getMagic() {
		return f_magic;
	}

	/**
	 * @return the f_nscns
	 */
	public short getNscns() {
		return f_nscns;
	}

	/**
	 * @return the f_timdat
	 */
	public int getTimdat() {
		return f_timdat;
	}

	/**
	 * @return the f_symptr
	 */
	public int getSymptr() {
		return f_symptr;
	}

	/**
	 * @return the f_nsyms
	 */
	public int getNsyms() {
		return f_nsyms;
	}

	/**
	 * @return the f_opthdr
	 */
	public short getOpthdr() {
		return f_opthdr;
	}

	/**
	 * @return the f_flags
	 */
	public short getFlags() {
		return f_flags;
	}
	
}
