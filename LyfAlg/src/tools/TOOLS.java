package tools;

public class TOOLS {
	private volatile static TOOLS uniqueInstance;
//	private LOG log = LOG.getInstance();
	
	private final byte[] MASK = {(byte) 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01};
	
	private TOOLS() {}
	
	public static TOOLS getInstance() {
		if( null == uniqueInstance ) {
			synchronized (TOOLS.class) {
				if( null == uniqueInstance )
					uniqueInstance = new TOOLS();
			}
		}
		return uniqueInstance;
	}
	
	public void zeroArray(byte[] v) {
		if( null == v )
			return ;
		
		for(int i = 0; i < v.length; ++i) v[i] = 0;
	}
	
	public void zeroArray(int[] v) {
		if( null == v )
			return ;
		
		for(int i = 0; i < v.length; ++i) v[i] = 0;
	}
	
	public byte[] newArray(int size) {
		byte[] r = new byte[size];
		
		zeroArray(r);
		
		return r;
	}
	
	public Boolean copyArray(byte[] from, int fromstart, int frombytes, byte[] to, int tostart) {
		if( null == from || 0 == from.length || null == to || 0 == to.length || (to.length-tostart) < frombytes || (fromstart+frombytes > from.length) ) {
			System.err.println("copyArray(): return false");
			return false;
		}
		
		for(int i = 0; i < frombytes; ++i) {
			to[i+tostart] = from[i+fromstart];
		}
		
		return true;
	}
	
	public Boolean copyArray(int[] from, int fromstart, int frombytes, int[] to, int tostart) {
		if( null == from || 0 == from.length || null == to || 0 == to.length || (to.length-tostart) < frombytes || (fromstart+frombytes > from.length) ) {
			System.err.println("copyArray(): return false");
			return false;
		}
		
		for(int i = 0; i < frombytes; ++i) {
			to[i+tostart] = from[i+fromstart];
		}
		
		return true;
	}
	
	public int xor(int a, int b) {
		return (int) a ^ b;
	}
	
	public int add(int a, int b) {
		return (int) (a + b)%(2^32);
	}
	
	public Boolean xor(byte[] a, byte[] b, byte[] to) {
		if( null == a || 0 == a.length || null == b || 0 == b.length || a.length != b.length ) {
			System.err.println("xor(): return false");
			return false;
		}
		
		for(int i = 0; i < to.length; ++i) {
			to[i] = (byte) (a[i] ^ b[i]);
		}
		
//		log.printBytesInHEX("xor().a", a);
//		log.printBytesInHEX("xor().b", b);
//		log.printBytesInHEX("xor().to", to);
		
		return true;
	}
	
	//nbits <= 8
	public Boolean leftShiftNBits(byte[] from, int startbit, int nbits, byte[] to) {
		if( null == from || 0 == from.length || (startbit+nbits) > from.length*8 || nbits > 8 || nbits < 0 || startbit >= from.length*8 || startbit < 0 ) {
			System.err.println("leftNBits(): return false");
			return false;
		}
		
		byte[] frombits = new byte[from.length*8];
		byte[] tobits = new byte[nbits];
		this.bytes2Bits(from, 0, from.length*8, frombits, 0);
		for(int i = 0; i < nbits; ++i ) {
			tobits[i] = frombits[i+startbit];
		}
		
		this.bits2Bytes(tobits, 0, tobits.length, to, 0);
		return true;
	}
	
	//from can overlap to
	public Boolean leftShiftNBytes(byte[] from, int startbyte, int nbytes, byte[] to, int tostart, int leftshiftn) {
		if( null == from || 0 == from.length || null == to || 
				(to.length-tostart) < nbytes || (startbyte+nbytes) > from.length || 
				startbyte >= from.length || nbytes < 0 || leftshiftn < 0 ) {
			System.err.println("leftShiftNBytes(): return false");
			return false;
		}
		
		byte[] totemp = new byte[nbytes];
		this.copyArray(from, startbyte+(leftshiftn%nbytes), nbytes-(leftshiftn%nbytes), totemp, 0);
		this.copyArray(from, startbyte, leftshiftn%nbytes, totemp, nbytes-(leftshiftn%nbytes));
		this.copyArray(totemp, 0, nbytes, to, tostart);

		return true;
	}
	
	public Boolean bytes2Bits(byte[] from, int fromstart, int frombits, byte[] to, int tostart) {
		if( null == from || 0 == from.length || null == to || 0 == to.length || (to.length-tostart) < frombits || (fromstart+frombits/8+((frombits%8==0)?0:1) > from.length) ) {
			System.err.println("bytes2Bits(): return false");
			return false;
		}
		
		for(int i = 0; i < frombits; ++i) {
			if( 0 == (from[i/8] & MASK[i%8]) )
				to[i+tostart] = 0;
			else
				to[i+tostart] = 1;
		}
		return true;
	}
	
	public Boolean bits2Bytes(byte[] from, int fromstart, int frombits, byte[] to, int tostart) {
		if( null == from || 0 == from.length || null == to || 0 == to.length || (to.length-tostart) < frombits/8 || (fromstart+frombits > from.length) ) {
			System.err.println("bits2Bytes(): return false");
			return false;
		}
		
		for(int i = 0; i < frombits; ++i) {
			if( 0 == from[i+fromstart] )
				to[i/8+tostart] = (byte) (to[i/8+tostart] & (byte)~MASK[i%8]);
			else
				to[i/8+tostart] = (byte) (to[i/8+tostart] | (byte)MASK[i%8]);
		}
		return true;
	}
	
	//integer
//	public int rotateLeftNbits(int v, int n) {
//		int mask = 0x80000000, lmask =0, hmask =0;
//		
//		n = n % 32;
//
//		lmask = (mask >> (n-1) ) & 0x0ffffffff;
//		hmask = ~lmask;
//		
////		System.err.printf("lmask = 0x%08x, hmask = 0x%08x, high = 0x%08x, low = 0x%08x\n", lmask, hmask, (v&hmask) << n, (v&lmask) >>> (32-n));
//		return ((v&hmask) << n) | ((v&lmask) >>> (32-n));
//	}
	
	//integer to bytes[4], MSB
	public Boolean integerTo4BytesMSB(int from, byte[] to, int tostart) {
		if( null == to || 4 > (to.length+tostart) ) return false;
		
		to[0+tostart] = (byte) ((from & 0x0ff000000) >>> 24);
		to[1+tostart] = (byte) ((from &  0x00ff0000) >>> 16);
		to[2+tostart] = (byte) ((from &  0x0000ff00) >>> 8);
		to[3+tostart] = (byte) (from &  0x000000ff);

		return true;
	}
	
	// integer to bytes[4], LSB
	public Boolean integerTo4BytesLSB(int from, byte[] to, int tostart) {
		if( null == to || 4 > (to.length+tostart) ) return false;
		
		to[3+tostart] = (byte) ((from & 0x0ff000000) >>> 24);
		to[2+tostart] = (byte) ((from &  0x00ff0000) >>> 16);
		to[1+tostart] = (byte) ((from &  0x0000ff00) >>> 8);
		to[0+tostart] = (byte) (from &  0x000000ff);

		return true;
	}
	
	//integers to bytes
	public byte[] integerArrayToByteArray(int[] from) {
		if( null == from )
			return null;
		
		byte[] to = new byte[from.length*4];
		
		for(int i = 0; i < from.length; ++i) {
			to[i*4] = (byte) (from[i] & 0x0ff000000 >>> 24);
			to[i*4+1] = (byte) (from[i] & 0x00ff0000 >>> 16);
			to[i*4+2] = (byte) (from[i] & 0x0000ff00 >>> 8);
			to[i*4+3] = (byte) (from[i] & 0x000000ff);
		}
		
		return to;
	}
	
	//long to byte[8], MSB
	public Boolean longTo8BytesMSB(long from, byte[] to, int tostart) {
		if( null == to || 8 > (to.length+tostart) ) return false;
		
		to[0+tostart] = (byte) ((from & 0x0ff00000000000000L) >>> 56);
		to[1+tostart] = (byte) ((from &  0x00ff000000000000L) >>> 48);
		to[2+tostart] = (byte) ((from &  0x0000ff0000000000L) >>> 40);
		to[3+tostart] = (byte) ((from &  0x000000ff00000000L) >>> 32);
		to[4+tostart] = (byte) ((from &  0x00000000ff000000L) >>> 24);
		to[5+tostart] = (byte) ((from &  0x0000000000ff0000L) >>> 16);
		to[6+tostart] = (byte) ((from &  0x000000000000ff00L) >>> 8);
		to[7+tostart] = (byte) (from &   0x00000000000000ffL);
		return true;
	}
	
	//long to byte[16], MSB
	public Boolean longTo16BytesMSB(long from, byte[] to, int tostart) {
		if( null == to || 8 > (to.length+tostart) ) return false;
		
		to[0+tostart] = 0;
		to[1+tostart] = 0;
		to[2+tostart] = 0;
		to[3+tostart] = 0;
		to[4+tostart] = 0;
		to[5+tostart] = 0;
		to[6+tostart] = 0;
		to[7+tostart] = 0;
		to[8+tostart] = (byte) ((from &   0x0ff0000000000000L) >>> 56);
		to[9+tostart] = (byte) ((from &   0x00ff000000000000L) >>> 48);
		to[10+tostart] = (byte) ((from &  0x0000ff0000000000L) >>> 40);
		to[11+tostart] = (byte) ((from &  0x000000ff00000000L) >>> 32);
		to[12+tostart] = (byte) ((from &  0x00000000ff000000L) >>> 24);
		to[13+tostart] = (byte) ((from &  0x0000000000ff0000L) >>> 16);
		to[14+tostart] = (byte) ((from &  0x000000000000ff00L) >>> 8);
		to[15+tostart] = (byte) (from &   0x00000000000000ffL);
		return true;
	}
}
