package des;

import tools.TOOLS;
import tools.LOG;

public class DES_IP {
	private TOOLS tools = TOOLS.getInstance();
	private LOG log = LOG.getInstance();
	
	private volatile static DES_IP uniqueInstance;
	
	private DES_IP() {}
	
	public static DES_IP getInstance() {
		if( null == uniqueInstance ) {
			synchronized (DES_IP.class) {
				if( null == uniqueInstance )
					uniqueInstance = new DES_IP();
			}
		}
		return uniqueInstance;
	}
	
	private final byte table[] = {
			58,50,42,34,26,18,10,2,
			60,52,44,36,28,20,12,4,
			62,54,46,38,30,22,14,6,
			64,56,48,40,32,24,16,8,
			57,49,41,33,25,17, 9,1,
			59,51,43,35,27,19,11,3,
			61,53,45,37,29,21,13,5,
			63,55,47,39,31,23,15,7
	};
	public final int DES_IP_BITS = table.length;
	
	// fromtext.len = 8, l.len = 4, r.len = 4
	public Boolean exec(byte[] fromtext, byte[] l, byte[] r) {
		if( null == fromtext || null == l || null == r || 
				fromtext.length != DES_IP_BITS/8 || l.length != DES_IP_BITS/(2*8) || r.length != DES_IP_BITS/(2*8) ) {
			System.err.println("IP(): return false");
			return false;
		}
		
		byte[] fromtextbits = new byte[DES_IP_BITS];
		tools.bytes2Bits(fromtext, 0, fromtext.length*8, fromtextbits, 0);
		
		byte[] totextbits = new byte[DES_IP_BITS];
		for(int i = 0; i < DES_IP_BITS; ++i) {
			totextbits[i] = fromtextbits[table[i]-1];
		}
		
		tools.bits2Bytes(totextbits, 0, DES_IP_BITS/2, l, 0);
		tools.bits2Bytes(totextbits, DES_IP_BITS/2, DES_IP_BITS/2, r, 0);

		log.printBytesInHEX("IP().fromtext", fromtext);
		log.printBytesInHEX("IP().l", l);
		log.printBytesInHEX("IP().r", r);
		
		return true;
	}
}
