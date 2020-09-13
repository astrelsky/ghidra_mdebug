package mdebug.ecoff;

import java.util.Iterator;
import java.util.List;

import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.exception.AssertException;

/**
 * ECOFF Type Information Record
 */
public class EcoffTir implements Iterable<EcoffTypeQualifier> {

	private static final byte NIBBLE_MASK = (byte) 0x0f;
	private static final byte NIBBLE_SIZE = (byte) 4;

	private final boolean bitfieldFlag;
	private final boolean continued;
	private final EcoffBasicType basicType;

	private final EcoffTypeQualifier typeQualifier0;
	private final EcoffTypeQualifier typeQualifier1;
	private final EcoffTypeQualifier typeQualifier2;
	private final EcoffTypeQualifier typeQualifier3;
	private final EcoffTypeQualifier typeQualifier4;
	private final EcoffTypeQualifier typeQualifier5;

	static final DataType dataType = getDataType();

	EcoffTir(int data) {
		Scalar scalar = new Scalar(Integer.BYTES << 3, data, false);
		final byte[] bytes = scalar.byteArrayValue();
		scalar = new Scalar(Byte.BYTES << 3, bytes[0], false);
		this.bitfieldFlag = scalar.testBit(1);
		this.continued = scalar.testBit(2);
		this.basicType = EcoffBasicType.toEnum(bytes[0] >> 2);

		this.typeQualifier4 = EcoffTypeQualifier.toEnum(bytes[1] & NIBBLE_MASK);
		this.typeQualifier5 = EcoffTypeQualifier.toEnum(bytes[1] >> NIBBLE_SIZE);

		this.typeQualifier0 = EcoffTypeQualifier.toEnum(bytes[2] & NIBBLE_MASK);
		this.typeQualifier1 = EcoffTypeQualifier.toEnum(bytes[2] >> NIBBLE_SIZE);

		this.typeQualifier2 = EcoffTypeQualifier.toEnum(bytes[3] & NIBBLE_MASK);
		this.typeQualifier3 = EcoffTypeQualifier.toEnum(bytes[3] >> NIBBLE_SIZE);
	}

	/**
	 * @return true if a bitfield
	 */
	public boolean isBitfield() {
		return bitfieldFlag;
	}

	/**
	 * @return true if continued
	 */
	public boolean isContinued() {
		return continued;
	}

	/**
	 * @return the basic type
	 */
	public EcoffBasicType getBasicType() {
		return basicType;
	}

	private static final DataType getDataType() {
		try {
			Structure struct = new StructureDataType(EcoffHdrr.ECOFF_PATH, "TIR", 0);
			struct.addBitField(BooleanDataType.dataType, 1, "fBitfield", null);
			struct.addBitField(BooleanDataType.dataType, 1, "continued", null);
			struct.addBitField(EcoffBasicType.dataType, 6, "bt", null);

			// the type qualifier order is 4,5,0,1,2,3
			struct.addBitField(EcoffTypeQualifier.dataType, 4, "tq4", null);
			struct.addBitField(EcoffTypeQualifier.dataType, 4, "tq5", null);
			struct.addBitField(EcoffTypeQualifier.dataType, 4, "tq0", null);
			struct.addBitField(EcoffTypeQualifier.dataType, 4, "tq1", null);
			struct.addBitField(EcoffTypeQualifier.dataType, 4, "tq2", null);
			struct.addBitField(EcoffTypeQualifier.dataType, 4, "tq3", null);
			struct.setToMachineAlignment();
			return struct;
		} catch (InvalidDataTypeException e) {
			throw new AssertException(e);
		}
	}

	@Override
	public Iterator<EcoffTypeQualifier> iterator() {
		return List.of(
			typeQualifier5, typeQualifier4, typeQualifier3,
			typeQualifier2, typeQualifier1, typeQualifier0
		).iterator();
	}

}
