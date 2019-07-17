package des;

import tools.TOOLS;
import tools.LOG;

public class DES_SBOX {
	private TOOLS tools = TOOLS.getInstance();
	private LOG log = LOG.getInstance();
	
	private volatile static DES_SBOX uniqueInstance;
	
	private DES_SBOX() {}
	
	public static DES_SBOX getInstance() {
		if( null == uniqueInstance ) {
			synchronized (DES_SBOX.class) {
				if( null == uniqueInstance )
					uniqueInstance = new DES_SBOX();
			}
		}
		return uniqueInstance;
	}
	
	private final byte[][] box = {{
		14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7, 
		0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8, 
		4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0, 
		15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
	},
	{
		15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10, 
		3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5, 
		0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15, 
		13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
	},
	{
		10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8, 
		13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1, 
		13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7, 
		1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
	},
	{
		7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15, 
		13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9, 
		10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4, 
		3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
	},
	{
		2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9, 
		14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6, 
		4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14, 
		11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
	},
	{
		12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11, 
		10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8, 
		9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6, 
		4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
	},
	{
		4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1, 
		13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6, 
		1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2, 
		6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
	},
	{
		13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7, 
		1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2, 
		7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8, 
		2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
	}};
	public final int DES_SBOX_COUNT = box.length;

	public final int DES_SBOX_ALL_INPUT_BITS = 48;
	public final int DES_SBOX_RESULT_BITS = 32;
	public final int DES_SBOX_A_BOX_INPUT_BITS = 6;
	
	private int getRow(byte b1, byte b6) {
		return b1<<1 | b6;
	}
	
	private int getColumn(byte b2, byte b3, byte b4, byte b5) {
		return  b2<<3 | b3 << 2 | b4 << 1 | b5;
	}
	
	private Boolean getValue(int sidx, byte[] to, byte b1, byte b2, byte b3, byte b4, byte b5, byte b6) {
		if( sidx < 0 || sidx >= DES_SBOX_COUNT || null == to || to.length != 1 ) {
			System.err.println("SBOX().getValue: return false");
			return false;
		}
		
		int row = getRow(b1, b6);
		int column = getColumn(b2, b3, b4, b5);
		
		to[0] = box[sidx][row*16+column];
		
		return true;
	}
	
	public Boolean exec(byte[] from, byte[] to) {
	if( null == from || DES_SBOX_ALL_INPUT_BITS/8 != from.length || null == to || DES_SBOX_RESULT_BITS/8 != to.length ) {
		System.err.println("sBox(): return false");
		return false;
	}
	
	byte[] frombits = new byte[from.length*8];
	tools.bytes2Bits(from, 0, from.length*8, frombits, 0);
	
	byte[] boxvalue = new byte[1];
	for(int i = 0; i < frombits.length; i=i+DES_SBOX_A_BOX_INPUT_BITS) {
		if( !getValue(i/DES_SBOX_A_BOX_INPUT_BITS, boxvalue, frombits[i], frombits[i+1],frombits[i+2],frombits[i+3],frombits[i+4], frombits[i+5]) ) {
			System.err.println("sBox().box.getValue: return false");
			return false;
		}
		
		to[i/(DES_SBOX_A_BOX_INPUT_BITS*2)] = 
				(byte) (to[i/(DES_SBOX_A_BOX_INPUT_BITS*2)] |
						(boxvalue[0] << (0 == ((i/DES_SBOX_A_BOX_INPUT_BITS)&0x01)?4:0) ) );
	}
	
	log.printBytesInHEX("sBox().to", to);
	return true;
	}
}
