package mdebug.ecoff;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;

public final class FileOffsetAddressFinder {

	private final Memory mem;

	FileOffsetAddressFinder(Memory mem) {
		this.mem = Objects.requireNonNull(mem);
	}

	Address findAddress(long offset) {
		return Arrays.stream(mem.getBlocks())
			.filter(Predicate.not(MemoryBlock::isMapped))
			.filter(MemoryBlock::isInitialized)
			.map(MemoryBlock::getSourceInfos)
			.flatMap(List::stream)
			.filter(info -> containsOffset(info, offset))
			.findFirst()
			.map(info -> getAddress(info, offset))
			.orElse(null);
	}

	private boolean containsOffset(MemoryBlockSourceInfo info, long offset) {
		long start = info.getFileBytesOffset();
		long end = start + info.getLength();
		return start <= offset && end >= offset;
	}

	private Address getAddress(MemoryBlockSourceInfo info, long offset) {
		offset -= info.getFileBytesOffset();
		return info.getMinAddress().add(offset);
	}

	Program getProgram() {
		return mem.getProgram();
	}

	Memory getMemory() {
		return mem;
	}
}
