package des;

import java.io.UnsupportedEncodingException;

import tools.TOOLS;
import tools.LOG;

public class DES_KEY {
	private TOOLS tools = TOOLS.getInstance();
	private LOG log = LOG.getInstance();
	
	public final int DES_KEY_MAX_BYTES = 8;
	
	private final byte ps1_table[] = {
		//c
		57,49,41,33,25,17,9,
		1,58,50,42,34,26,18,
		10,2,59,51,43,35,27,
		19,11,3,60,52,44,36,
		
		//d
		63,55,47,39,31,23,15,
		7,62,54,46,38,30,22,
		14,6,61,53,45,37,29,
		21,13,5,28,20,12,4
	};
	public final int DES_KEY_PS1_BITS = ps1_table.length;
	
	private final byte ps2_table[] = {
			14,17,11,24,1,5,3,28,
			15,6,21,10,23,19,12,4,
			26,8,16,7,27,20,13,2,
			41,52,31,37,47,55,30,40,
			51,45,33,48,44,49,39,56,
			34,53,46,42,50,36,29,32
	};
	public final int DES_KEY_PS2_BITS = ps2_table.length;
	
	private final byte[] ROTATE_LEFT_BITS = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
	private final int DES_ROTATE_LEFT_TIMES = ROTATE_LEFT_BITS.length;
	
	private final byte[] MASK = {(byte) 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01};
	
	private byte[] key = {0,0,0,0,0,0,0,0};
	private byte[] c = {0,0,0,0};
	private byte[] d = {0,0,0,0};
	
	public final int DES_SUBKEY_COUNT = 16;
	public final int DES_SUBKEY_BYTES = 6;
	private byte[][] subkeys = {
			{0,0,0,0,0,0},{0,0,0,0,0,0},{0,0,0,0,0,0},{0,0,0,0,0,0},
			{0,0,0,0,0,0},{0,0,0,0,0,0},{0,0,0,0,0,0},{0,0,0,0,0,0},
			{0,0,0,0,0,0},{0,0,0,0,0,0},{0,0,0,0,0,0},{0,0,0,0,0,0},
			{0,0,0,0,0,0},{0,0,0,0,0,0},{0,0,0,0,0,0},{0,0,0,0,0,0}
			};
	
	
	public DES_KEY(String k) {
		if( null == k ) {
			return ;
		}
			
		try {
			byte tmp[] = k.getBytes("US-ASCII");
			initKey(tmp);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	}
	
	public DES_KEY(byte[] k) {
		initKey(k);
	}
	
	public void initKey(byte[] k) {
		int len = k.length>key.length?key.length:k.length;
		
		tools.copyArray(k, 0, len, key, 0);
	}
	
	private void generatePS1C() {
		byte mask = 0;
		int frombyteoff = 0;
		int frombitoff = 0;
		int tobyteoff = 0;
		byte tmpfrom = 0;
		
		//c
		for (int i = 0; i < DES_KEY_PS1_BITS/2; ++i) {
			tobyteoff = i / 8;
			frombyteoff = (ps1_table[i] - 1) / 8;
			frombitoff = 7 - (ps1_table[i] - 1) % 8;
			mask = (byte) (0x01 << frombitoff);
			
//			System.err.printf("i=%d, c[%d]=%s, key[%d]=%s, from.bitoff=%d, mask=%s, ", 
//					i, 
//					tobyteoff, Log.getByteInBinary(c[tobyteoff]),
//					frombyteoff,Log.getByteInBinary(key[frombyteoff]), 
//					frombitoff, Log.getByteInBinary(mask));

			tmpfrom = (byte) ((key[frombyteoff] & 0xff & mask) << (7-frombitoff) >>> (i%8));
			c[tobyteoff] = (byte) ( c[tobyteoff] | tmpfrom );

//			System.err.printf("tmpfrom=%s, after.c[%d]=%s\n", Log.getByteInBinary(tmpfrom), tobyteoff, Log.getByteInBinary(c[tobyteoff]));
		}
		
//		Log.printBytesInBinary("C0", c, 7, DES_KEY_PS1_BITS/2);
	}
	
	private void generatePS1D() {
		byte mask = 0;
		int frombyteoff = 0;
		int frombitoff = 0;
		int tobyteoff = 0;
		byte tmpfrom = 0;
		
		//d
		for (int i = 0; i < DES_KEY_PS1_BITS/2; ++i) {
			tobyteoff = i / 8;
			frombyteoff = (ps1_table[i+DES_KEY_PS1_BITS/2] - 1) / 8;
			frombitoff = 7 - (ps1_table[i+DES_KEY_PS1_BITS/2] - 1) % 8;
			mask = (byte) (0x01 << frombitoff);
			
//			System.err.printf("i=%d, d[%d]=%s, key[%d]=%s, from.bitoff=%d, mask=%s, ", 
//					i, 
//					tobyteoff, Log.getByteInBinary(d[tobyteoff]),
//					frombyteoff,Log.getByteInBinary(key[frombyteoff]), 
//					frombitoff, Log.getByteInBinary(mask));

			tmpfrom = (byte) ((key[frombyteoff] & 0xff & mask) << (7-frombitoff) >>> (i%8));
			d[tobyteoff] = (byte) ( d[tobyteoff] | tmpfrom );

//			System.err.printf("tmpfrom=%s, after.d[%d]=%s\n", Log.getByteInBinary(tmpfrom), tobyteoff, Log.getByteInBinary(d[tobyteoff]));
		}
		
//		Log.printBytesInBinary("D0", d, 7, DES_KEY_PS1_BITS/2);
	}
	
	public void rotateLeftNBits(byte[] value, int usedbits, int shiftbits) {
		if( usedbits > value.length*8 )
			return ;
		
		shiftbits = shiftbits % usedbits;
		
		byte[] t = new byte[usedbits];
		tools.bytes2Bits(value, 0, usedbits, t, 0);
		
		//left shift bits
		byte[] lefttemp = new byte[shiftbits];
		for(int i = 0; i < shiftbits; ++i) {
			lefttemp[i] = t[i];
		}
		for(int i = 0; i < usedbits-shiftbits; ++i) {
			t[i] = t[i+shiftbits];
		}
		for(int i = 0; i < shiftbits; ++i) {
			t[i+usedbits-shiftbits] = lefttemp[i];
		}
		
		tools.bits2Bytes(t, 0, t.length, value, 0);
	}
	
	//permutation selector
	private byte[] PS2() {
		//1。compact c, d to an array cd
		byte[] cbits = new byte[DES_KEY_PS1_BITS/2];
		byte[] dbits = new byte[DES_KEY_PS1_BITS/2];
		
		tools.bytes2Bits(c, 0, DES_KEY_PS1_BITS/2, cbits, 0);
		tools.bytes2Bits(d, 0, DES_KEY_PS1_BITS/2, dbits, 0);
		
		byte[] cdbits = new byte[DES_KEY_PS1_BITS];
		tools.copyArray(cbits, 0, cbits.length, cdbits, 0);
		tools.copyArray(dbits, 0, dbits.length, cdbits, cbits.length);		
	
//		byte[] cd = new byte[cdbits.length/8];
//		tools.bits2Bytes(cdbits, 0, cdbits.length, cd, 0);
//	
//		Log.printBytesInDEC("cdbits=", cdbits);
		
		//2. ip2
		int tobyteoff = 0;
		int tobitoff = 0;
		byte[] r = tools.newArray(DES_KEY_PS2_BITS/8);
		for(int i = 0; i < DES_KEY_PS2_BITS; ++i) {
			tobyteoff = i/8;
			tobitoff = i%8;
			if( 0 == cdbits[ps2_table[i]-1] )
				r[tobyteoff] = (byte) (r[tobyteoff] & (byte)~MASK[tobitoff]);
			else
				r[tobyteoff] = (byte) (r[tobyteoff] | (byte)MASK[tobitoff]);
		}
		
//		Log.printBytesInBinary("after IP2", r);
		return r;
	}
	
	public Boolean generateSubKeys() {
		//1. remove parity bit
		//k = removeParityBits(orgkey.getBytes("US-ASCII"));

		System.err.printf("generateSubKeys() ==== start ====\n");
		log.printBytesInBinary("original key=", key);
		
		//2. PS1
		generatePS1C();
		generatePS1D();
		
		//3. generate 16 groups key
		for(int i =0; i < DES_ROTATE_LEFT_TIMES; ++i) {
			rotateLeftNBits(c, DES_KEY_PS1_BITS/2, ROTATE_LEFT_BITS[i]);
			rotateLeftNBits(d, DES_KEY_PS1_BITS/2, ROTATE_LEFT_BITS[i]);
		
//			System.err.printf("i=%d, shift bit = %d\n", i, ROTATE_LEFT_BITS[i]);
//			Log.printBytesInBinary("C"+(i+1), c, 7, DES_KEY_PS1_BITS/2);
//			Log.printBytesInBinary("D"+(i+1), d, 7, DES_KEY_PS1_BITS/2);
			
			//PS2
			subkeys[i] = PS2();
			log.printBytesInBinary("subKey"+(i+1), subkeys[i], 6, 6*8);
		}
		
		System.err.printf("generateSubKeys() ==== end ====\n");
		
		return true;
	}
	
	public byte[] getSubkey(int idx) {
		if( idx < 0 || idx >= DES_SUBKEY_COUNT )
			return subkeys[0];
		
		return subkeys[idx];
	}
}
