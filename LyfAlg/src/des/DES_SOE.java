package des;

import tools.TOOLS;
import tools.LOG;

public class DES_SOE {
	private TOOLS tools = TOOLS.getInstance();
	private LOG log = LOG.getInstance();
	
	private volatile static DES_SOE uniqueInstance;
	
	private DES_SOE() {}
	
	public static DES_SOE getInstance() {
		if( null == uniqueInstance ) {
			synchronized (DES_SOE.class) {
				if( null == uniqueInstance )
					uniqueInstance = new DES_SOE();
			}
		}
		return uniqueInstance;
	}
	
	private final byte table[] = {
			32,1,2,3,4,5,4,5,
			6,7,8,9,8,9,10,11,
			12,13,12,13,14,15,16,17,
			16,17,18,19,20,21,20,21,
			22,23,24,25,24,25,26,27,
			28,29,28,29,30,31,32,1
		};
	public final int DES_SOE_RESULT_BITS = table.length;
	public final int DES_SOE_INPUT_BITS = 32;
	
	public Boolean exec(byte[] from, byte[] to) {
		if( null == from || 0 == from.length || null == to || 0 == to.length || 
				from.length != DES_SOE_INPUT_BITS/8 || to.length != DES_SOE_RESULT_BITS/8) {
			System.err.println("SOE(): return false");
			return false;
		}
		
		byte[] frombits = new byte[from.length*8];
		tools.bytes2Bits(from, 0, from.length*8, frombits, 0);
		
//			Log.printBytesInDEC("SelectE().rbits", rbits);
		
		byte[] tobits = new byte[DES_SOE_RESULT_BITS];
		for(int i = 0; i < tobits.length; ++i ) {
			tobits[i] = frombits[table[i]-1];
		}
		
//			Log.printBytesInDEC("SelectE().erbits", erbits);
		
		tools.bits2Bytes(tobits, 0, tobits.length, to, 0);
		
		log.printBytesInHEX("SOE().from", from);
		log.printBytesInHEX("SOE().to", to);
		
		return true;
	}
}
