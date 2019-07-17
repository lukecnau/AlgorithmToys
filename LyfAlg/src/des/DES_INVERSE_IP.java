package des;

import tools.TOOLS;
import tools.LOG;

public class DES_INVERSE_IP {
	private TOOLS tools = TOOLS.getInstance();
	private LOG log = LOG.getInstance();
	
	private volatile static DES_INVERSE_IP uniqueInstance;
	
	private DES_INVERSE_IP() {}
	
	public static DES_INVERSE_IP getInstance() {
		if( null == uniqueInstance ) {
			synchronized (DES_INVERSE_IP.class) {
				if( null == uniqueInstance )
					uniqueInstance = new DES_INVERSE_IP();
			}
		}
		return uniqueInstance;
	}
	
	private final byte table[] = {
			40,8,48,16,56,24,64,32,
			39,7,47,15,55,23,63,31,
			38,6,46,14,54,22,62,30,
			37,5,45,13,53,21,61,29,
			36,4,44,12,52,20,60,28,
			35,3,43,11,51,19,59,27,
			34,2,42,10,50,18,58,26,
			33,1,41, 9,49,17,57,25
	};
	public final int DES_INVERSE_IP_BITS = table.length;
	
	// l.len = 4, r.len = 4, totext.len = 8
	public Boolean exec(byte[] l, byte[] r, byte[] totext) {
		if( null == totext || null == l || null == r || 0 == totext.length || 0 == l.length || 0 == r.length ||
				totext.length != DES_INVERSE_IP_BITS/8 || l.length != DES_INVERSE_IP_BITS/(2*8) || r.length != DES_INVERSE_IP_BITS/(2*8) ) {
			System.err.println("inverseIP(): return false");
			return false;
		}
		
		byte[] fromtextbits = new byte[DES_INVERSE_IP_BITS];
		
		tools.bytes2Bits(l, 0, l.length*8, fromtextbits, 0);
		tools.bytes2Bits(r, 0, r.length*8, fromtextbits, DES_INVERSE_IP_BITS/2);
		
		byte[] totextbits = new byte[DES_INVERSE_IP_BITS];
		for(int i = 0; i < DES_INVERSE_IP_BITS; ++i) {
			totextbits[i] = fromtextbits[table[i]-1];
		}
		
		tools.bits2Bytes(totextbits, 0, DES_INVERSE_IP_BITS, totext, 0);
		
		log.printBytesInHEX("inverseIP().l", l);
		log.printBytesInHEX("inverseIP().r", r);
		log.printBytesInHEX("inverseIP().totext", totext);
		return true;
	}
}
