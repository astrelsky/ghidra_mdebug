package mdebug.ecoff;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.ByteBuffer;

import ghidra.app.util.bin.ByteProvider;

public class EcoffMachineType {

	/**
	 * The contents of this field are assumed to be applicable to any machine type
	 */
	public final static short IMAGE_FILE_MACHINE_UNKNOWN = 0x0000;

	/**
	 * MIPS little-endian WCE v2
	 */
	public final static short IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x0169;

	public final static short IMAGE_FILE_MACHINE_MIPS_LE_ISA1 = 0x0162;
	public final static short IMAGE_FILE_MACHINE_MIPS_BE_ISA1 = 0x0160;

	public final static short IMAGE_FILE_MACHINE_MIPS_LE_ISA2 = 0x0166;
	public final static short IMAGE_FILE_MACHINE_MIPS_BE_ISA2 = 0x0163;

	public final static short IMAGE_FILE_MACHINE_MIPS_LE_ISA3 = 0x0142;
	public final static short IMAGE_FILE_MACHINE_MIPS_BE_ISA3 = 0x0140;

	public final static short IMAGE_FILE_MACHINE_ALPHA = 0x0183;
	public final static short IMAGE_FILE_MACHINE_ALPHA_BSD = 0x0185;

	// Would need to figure out how to decompress
	//public final static short IMAGE_FILE_MACHINE_ALPHA_COMPRESSED = 0x0188;

	/**
	 * Checks to see if the given machine type is defined in this file.
	 * 
	 * @param type The machine type to check.
	 * @return True if the given machine type is defined in this file; otherwise, false.
	 */
	public static boolean isMachineTypeDefined(short type) {
		if (type == IMAGE_FILE_MACHINE_UNKNOWN) {
			// This machine type is only defined in this file for completeness.
			// We want to treat this type as an unsupported machine.
			return false;
		}

		for (Field field : EcoffMachineType.class.getDeclaredFields()) {
			if (!field.isSynthetic()) {
				int modifiers = field.getModifiers();
				if (Modifier.isFinal(modifiers) && Modifier.isStatic(modifiers)) {
					try {
						if (field.getShort(null) == type) {
							return true;
						}
					}
					catch (IllegalAccessException e) {
						continue;
					}
				}
			}
		}
		return false;
	}

	public static boolean isBigEndian(ByteProvider provider) throws IOException {
		final short type = ByteBuffer.wrap(provider.readBytes(0, 2)).getShort();
		switch(type) {
			case IMAGE_FILE_MACHINE_MIPS_BE_ISA1:
			case IMAGE_FILE_MACHINE_MIPS_BE_ISA2:
			case IMAGE_FILE_MACHINE_MIPS_BE_ISA3:
				return true;
			default:
				return false;
		}
	}
}
