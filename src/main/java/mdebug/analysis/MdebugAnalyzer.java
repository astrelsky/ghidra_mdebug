package mdebug.analysis;

import java.util.Set;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.next.DWARFRegisterMappings;
import ghidra.app.util.bin.format.dwarf4.next.DWARFRegisterMappingsManager;
//import ghidra.app.util.bin.format.stabs.StabsParser;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerOptions;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.app.util.demangler.gnu.DemanglerParseException;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.CancelOnlyWrappingTaskMonitor;
import ghidra.util.task.TaskMonitor;

import mdebug.ecoff.*;

import static ghidra.program.model.symbol.SourceType.IMPORTED;

public final class MdebugAnalyzer extends AbstractAnalyzer {

	private static final String MDEBUG_ANALYZER_NAME = "MDEBUG";
	private static final String MDEBUG_ANALYZER_DESCRIPTION =
		"Automatically extracts mdebug info from an ELF file.";
	private static final String LANG_WARNING = "This file was not written in C/C++";
	private static final DemanglerOptions OPTIONS = new DemanglerOptions();

	private Program program;
	private MessageLog log;
	private TaskMonitor dummy;
	private EcoffHdrr hdrr;

	public MdebugAnalyzer() {
		super(MDEBUG_ANALYZER_NAME, MDEBUG_ANALYZER_DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after());
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return getMdebugBlock(program) != null;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		this.program = program;
		this.log = log;
		this.dummy = new CancelOnlyWrappingTaskMonitor(monitor);
		try {
			this.hdrr = EcoffHdrr.getHdrr(program);
			createData(hdrr.getAddress(), hdrr.toDataType());
			// file descriptor records
			if (EcoffFdr.dataType == null) {
				DataType dt = EcoffFdr.getDataType();
				createTable(dt, hdrr.getIfdMax(), hdrr.getFdrTableAddress());
			} else {
				createTable(EcoffFdr.dataType, hdrr.getIfdMax(), hdrr.getFdrTableAddress());
			}
			// local symbol records
			createTable(EcoffSymr.dataType, hdrr.getIsymMax(), hdrr.getSymrTableAddress());
			// procedure records
			if (hdrr.is64Bit()) {
				createTable(EcoffPdr.dataType64, hdrr.getIpdMax(), hdrr.getPdrTableAddress());
			}
			else {
				createTable(EcoffPdr.dataType, hdrr.getIpdMax(), hdrr.getPdrTableAddress());
			}
			// external table records
			createTable(EcoffExtr.dataType, hdrr.getIextMax(), hdrr.getExtrTableAddress());
			// optimization records (should be zero)
			// iOptMax refers to size of table, not max index
			//currentAddr = addressFinder.findAddress(hdrr.getOptrTableOffset());
			//createTable(EcoffOptr.dataType, hdrr.getIoptMax(), currentAddr, helper);
			// file indirect
			createTable(StructConverter.DWORD, hdrr.getCrfd(), hdrr.getRfdTableAddress());
			// dense number records
			createTable(EcoffDnr.dataType, hdrr.getIdnMax(), hdrr.getDnrTableAddress());
			// line numbers
			createTable(StructConverter.BYTE, hdrr.getCbLine(), hdrr.getLineNumTableAddress());
			// auxillary information
			createTable(EcoffAuxu.dataType, hdrr.getIauxMax(), hdrr.getAuxTableAddress());

			// string tables
			createStringTable(hdrr.getStringTableAddress(), hdrr.getIssMax());
			createStringTable(hdrr.getExtStringTableAddress(), hdrr.getIssExtMax());

			hdrr.parse(monitor);
			// leave the debug info parsing for an analyzer
			markupMdebug(hdrr, monitor);
			/*List<String> stabs = hdrr.getSymbols()
				.stream()
				.filter(EcoffSymr::isStab)
				.map(EcoffSymr::toString)
				.collect(Collectors.toList());
			if (!stabs.isEmpty()) {
				StabsParser parser = new StabsParser(program);
				parser.parse(stabs, monitor);
			}*/
		} catch (CancelledException e) {
			return false;
		} catch (Exception e) {
			log.appendException(e);
			return false;
		}
		return true;
	}

	private DataType resolve(DataType dt) {
		return program.getDataTypeManager().resolve(dt, DataTypeConflictHandler.KEEP_HANDLER);
	}

	private BookmarkManager getBookmarkManager() {
		return program.getBookmarkManager();
	}

	private void markupMdebug(EcoffHdrr hdrr, TaskMonitor monitor)
			throws Exception {
		monitor.initialize(hdrr.getFiles().size());
		monitor.setMessage("Analyzing File Descriptors");
		for (EcoffFdr file : hdrr.getFiles()) {
			monitor.checkCanceled();
			for (EcoffPdr pdr : file.procedures) {
				monitor.checkCanceled();
				markupProcedure(pdr);
			}
			for (EcoffSymr symr : file.symbols) {
				monitor.checkCanceled();
				markupSymbol(symr);
			}
			monitor.incrementProgress(1);
		}
	}

	private void checkLanguage(EcoffPdr pdr) {
		EcoffLanguageCode lang = pdr.getFile().getLang();
		switch (lang) {
			case C:
			case CPLUSPLUSV2:
			case NIL:
			case STDC:
				break;
			default:
				Address fAddr = getAddress(pdr.getAdr());
				getBookmarkManager().setBookmark(
					fAddr, BookmarkType.WARNING, LANG_WARNING, lang.name());
				break;
		}
	}

	private void markupProcedure(EcoffPdr pdr) throws Exception {
		pdr.getSymbol().getAuxu().getTir();
		EcoffFdr file = pdr.getFile();
		if (pdr.getAdr() == -1) {
			return;
		}
		EcoffSymr symbol = pdr.getSymbol();
		if (symbol == null) {
			// no procedure
			return;
		}
		checkLanguage(pdr);
		final Address fAddr;
		if (symbol.getSc() != EcoffSc.TEXT) {
			throw new AssertException(symbol.getSymbolName());
		}
		fAddr = getAddress(symbol.getValue());
		Function fun = getListing().getFunctionAt(fAddr);
		if (fun != null && !fun.getName().equals(pdr.getSymbolName())) {
			if (!fun.getSignatureSource().isHigherPriorityThan(IMPORTED)) {
				fun = applyFunctionName(fAddr, pdr.getSymbolName());
			}
		} else if (fun == null) {
			fun = applyFunctionName(fAddr, pdr.getSymbolName());
		}
		// if option
		if (fun != null) {
			fun.setRepeatableComment(file.getFileName());
			StackFrame frame = fun.getStackFrame();
			frame.setLocalSize(pdr.getFrameoffset());
			//fun.setComment(LINES)
		}
	}

	private Function applyFunctionName(Address addr, String name) throws Exception {
		DemangledObject o = null;
		try {
			o = DemanglerUtil.demangle(name);
		} catch (DemanglerParseException e) {
		}
		if (o != null) {
			o.applyTo(program, addr, OPTIONS, dummy);
		} else {
			Function fun = getListing().getFunctionAt(addr);
			try {
				if (fun != null) {
					fun.setName(name, IMPORTED);
					return fun;
				}
				CreateFunctionCmd cmd = new CreateFunctionCmd(
					name, addr, null, IMPORTED);
				cmd.applyTo(program);
			} catch (DuplicateNameException e) {
				SymbolTable table = program.getSymbolTable();
				for (Symbol s : table.getSymbols(addr)) {
					if (s.getName().equals(name)) {
						s.delete();
						fun.setName(name, IMPORTED);
						break;
					}
				}
			}
		}
		return getListing().getFunctionAt(addr);
	}

	private SymbolTable getSymbolTable() {
		return program.getSymbolTable();
	}

	private void markupSymbol(EcoffSymr symbol) throws Exception {
		Language language = program.getLanguage();
		DWARFRegisterMappings regMap = DWARFRegisterMappingsManager.getMappingForLang(language);
		Variable v = null;
		Address addr = getAddress(symbol.getValue());
		Function fun = getListing().getFunctionContaining(addr);
		if (fun == null) {
			return;
		}
		EcoffSt type = symbol.getSt();
		EcoffSc sClass = symbol.getSc();
		if (type == EcoffSt.NIL) {
			return;
		}
		if (type == EcoffSt.PROC || type == EcoffSt.STATICPROC) {
			// already processed
			return;
		}
		if (type == EcoffSt.LABEL) {
			getSymbolTable().createLabel(addr, symbol.getSymbolName(), IMPORTED);
			return;
		}
		if (sClass.equals(EcoffSc.ABS) || sClass.equals(EcoffSc.VAR)) {
			v = fun.getStackFrame().getVariableContaining(symbol.getValue());
		} else if (sClass.equals(EcoffSc.REGISTER) || sClass.equals(EcoffSc.VARREGISTER)) {
			Register r = regMap.getGhidraReg(symbol.getValue());
			if (r == null) {
				log.appendMsg(String.format(
					"Unknown Register Mapping %d", symbol.getValue()));
				return;
			}
			Set<Variable> vars = Set.of(fun.getVariables(VariableFilter.REGISTER_VARIABLE_FILTER));
			if (type.equals(EcoffSt.PARAM)) {
				vars = Set.of(fun.getParameters(VariableFilter.PARAMETER_FILTER));
			} else if (type.equals(EcoffSt.LOCAL)) {
				vars = Set.of(fun.getLocalVariables(VariableFilter.LOCAL_VARIABLE_FILTER));
			} else {
				return;
			}
			for (Variable var : vars) {
				if (r.equals(var.getRegister())) {
					v = var;
					break;
				}
			}
		}
		if (v == null) {
			return;
		}
		//EcoffTir tir = symbol.getAuxu().getTir();
	}

	private AddressSpace getDefaultSpace() {
		return program.getAddressFactory().getDefaultAddressSpace();
	}

	private Address getAddress(long offset) {
		return getDefaultSpace().getAddress(offset);
	}

	private Listing getListing() {
		return program.getListing();
	}

	private Data createData(Address addr, DataType dt) throws Exception {
		Listing listing = getListing();
		Data data = listing.getDataAt(addr);
		if (data != null && data.getDataType().isEquivalent(dt)) {
			return data;
		}
		return DataUtilities.createData(
			program, addr, dt, 0, false, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
	}

	private MemoryBlock getMdebugBlock(Program program) {
		return program.getMemory().getBlock(".mdebug");
	}

	private void createTable(DataType dt, int count, Address addr) throws Exception {
		dt = resolve(dt);
		if (addr != null && count > 0) {
			Array array = new ArrayDataType(dt, count, dt.getLength());
			createData(addr, array);
		}
	}

	private void createStringTable(Address addr, long maxSize) throws Exception {
		Address currentAddr = addr;
		long size = 0;
		while (size < maxSize) {
			Data data = createData(currentAddr, TerminatedStringDataType.dataType);
			if (data == null) {
				break;
			}
			size += data.getLength();
			try {
				currentAddr = addr.add(size);
			} catch (AddressOutOfBoundsException e) {
				break;
			}
		}
	}

}
