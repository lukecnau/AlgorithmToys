package bigInt;

public class bigInteger {
	private final int BIGINTEGER_BITS_2048 = 2048;
	public final int BIGINTEGER_BYTES_OF_BITS_2048 = BIGINTEGER_BITS_2048/8;
	private final int BIGINTEGER_BITS_1024 = 1024;
	public final int BIGINTEGER_BYTES_OF_BITS_1024 = BIGINTEGER_BITS_1024/8;

	private Byte[] bi;
	
	private bigInteger() {}
	
	public bigInteger(int bytes) {
		if( BIGINTEGER_BYTES_OF_BITS_2048 != bytes) {
			bi = new Byte[BIGINTEGER_BYTES_OF_BITS_1024];
		} else {
			bi = new Byte[BIGINTEGER_BYTES_OF_BITS_2048];
		}
	}
}
