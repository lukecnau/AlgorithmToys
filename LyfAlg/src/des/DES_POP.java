package des;

import tools.TOOLS;

public class DES_POP {
	private TOOLS tools = TOOLS.getInstance();
	
	private volatile static DES_POP uniqueInstance;
	
	private DES_POP() {}
	
	public static DES_POP getInstance() {
		if( null == uniqueInstance ) {
			synchronized (DES_POP.class) {
				if( null == uniqueInstance )
					uniqueInstance = new DES_POP();
			}
		}
		return uniqueInstance;
	}
	
	private final byte[] table = {
			16,7,20,21,29,12,28,17,
			1,15,23,26,5,18,31,10,
			2,8,24,14,32,27,3,9,
			19,13,30,6,22,11,4,25
		};
	public final int DES_POP_BITS = table.length;
	public final int DES_POP_INPUT_BITS = 32;
	public final int DES_POP_RESULT_BITS = 32;
	
	public Boolean exec(byte[] from, byte [] to) {
		if( null == from || 0 == from.length || null == to || 0 == to.length || from.length != DES_POP_INPUT_BITS/8 || to.length != DES_POP_RESULT_BITS/8 ) {
			System.err.println("POP(): return false");
			return false;
		}

		byte[] frombits = new byte[from.length*8];
		tools.bytes2Bits(from, 0, from.length*8, frombits, 0);

		byte[] tobits = new byte[to.length*8];
		for(int i = 0; i < tobits.length; ++i ) {
			tobits[i] = frombits[table[i]-1];
		}
		
		tools.bits2Bytes(tobits, 0, tobits.length, to, 0);
		return true;
	}
}
