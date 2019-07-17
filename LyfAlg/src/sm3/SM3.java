package sm3;

import tools.LOG;
import tools.TOOLS;

//spec: https://tools.ietf.org/html/draft-shen-sm3-hash-01
//online test:https://8gwifi.org/MessageDigest.jsp
//http://www.sca.gov.cn/sca/xwdt/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf

public class SM3 {
	TOOLS tools = TOOLS.getInstance();
	LOG log = LOG.getInstance();
	
	private final int SM3_A_BLOCK_WORDS = 16;
	private final int SM3_A_BLOCK_BYTES = SM3_A_BLOCK_WORDS*4;
	private final int SM3_A_BLOCK_BITS = SM3_A_BLOCK_BYTES*8;
	
	private final int SM3_A_BLOCK_USED_WORDS = SM3_A_BLOCK_WORDS-2;
	private final int SM3_A_BLOCK_USED_BYTES = SM3_A_BLOCK_USED_WORDS*4;
	private final int SM3_A_BLOCK_USED_BITS = SM3_A_BLOCK_USED_BYTES*8;
	
	private final static int SM3_OUTPUT_BYTES = 32;
	
	private static int[] SM3_V0 = { 
			0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e };
	
	private int[] paddingMessage(byte[] from) {
		byte[] to;
		if (null == from || 0 == from.length) {
			to = new byte[SM3_A_BLOCK_BYTES];
			to[0] = (byte) 0x80;

		} else if (from.length < SM3_A_BLOCK_USED_BYTES) {
			to = new byte[SM3_A_BLOCK_BYTES];
			tools.copyArray(from, 0, from.length, to, 0);
			to[from.length] = (byte) 0x80;
			tools.longTo8BytesMSB(from.length * 8, to, to.length - 8);

		} else { // from.length >= SM3_A_BLOCK_USED_BYTES
			to = new byte[((from.length+1) / SM3_A_BLOCK_BYTES + ((from.length+1) % SM3_A_BLOCK_BYTES <= SM3_A_BLOCK_USED_BYTES ? 1 : 2)) * SM3_A_BLOCK_BYTES];
			tools.copyArray(from, 0, from.length, to, 0);
			to[from.length] = (byte) 0x80;
			tools.longTo8BytesMSB(from.length * 8, to, to.length - 8);
		}
		
		int[] toint = new int[to.length/4];
		
		for(int i = 0; i < toint.length; ++i) {
			toint[i] = toint[i] | ((to[i*4]&0x0ff) << 24);
			toint[i] = toint[i] | ((to[i*4+1]&0x0ff) << 16);
			toint[i] = toint[i] | ((to[i*4+2]&0x0ff) << 8);
			toint[i] = toint[i] | (to[i*4+3]&0x0ff);
		}
		
		return toint;
	}
	
//	private int[] paddingMessage(byte[] from) {
//		byte[] to;
//		if( null == from || 0 == from.length ) {
//			to =  new byte[SM3_A_BLOCK_BYTES];
//			to[0] = (byte) 0x80;
//			
//		} else if( from.length < SM3_A_BLOCK_USED_BYTES ) {
//			to = new byte[SM3_A_BLOCK_BYTES];
//			tools.copyArray(from, 0, from.length, to, 0);
//			to[from.length] = (byte) 0x80;
//			tools.longTo8BytesMSB(from.length*8, to, to.length-8);
//		
//		} else { // from.length >= Sm3_A_BLOCK_USED_BYTES
//			to = new byte[(from.length/SM3_A_BLOCK_BYTES+(from.length% SM3_A_BLOCK_BYTES < SM3_A_BLOCK_USED_BYTES ? 1:2))*SM3_A_BLOCK_BYTES];
//			tools.copyArray(from, 0, from.length, to, 0);
//			if( 0 != from.length % SM3_A_BLOCK_BYTES )
//				to[from.length] = (byte) 0x80;
//			tools.longTo8BytesMSB(from.length*8, to, to.length-8);
//		}
//		
//		int[] toint = new int[to.length/4];
//		
//		for(int i = 0; i < toint.length; ++i) {
//			toint[i] = toint[i] | ((to[i*4]&0x0ff) << 24);
//			toint[i] = toint[i] | ((to[i*4+1]&0x0ff) << 16);
//			toint[i] = toint[i] | ((to[i*4+2]&0x0ff) << 8);
//			toint[i] = toint[i] | (to[i*4+3]&0x0ff);
//		}
//		
//		return toint;
//	}
	
	private int FF(int j, int x, int y, int z) {
		if( j >= 0 && j < 16 )
			return x ^ y ^ z;
		else if( j >= 16 && j < 64)
			return (x & y) | (x & z) | (y & z);
		else
			return 0;
	}
	
	private int GG(int j, int x, int y, int z) {
		if( j >= 0 && j < 16 )
			return x ^ y ^ z;
		else if( j >= 16 && j < 64)
			return (x & y) | (~x & z);
		else
			return 0;
	}
	
	private int P0(int x) {
		return x ^ Integer.rotateLeft(x, 9) ^ Integer.rotateLeft(x, 17);
	}
	
	private int P1(int x) {
		return x ^ Integer.rotateLeft(x, 15) ^ Integer.rotateLeft(x, 23);
	}
	
	private int T(int j) {
		if( j >= 0 && j < 16 )
			return 0x79cc4519;
		else if( j >= 16 && j < 64)
			return 0x7a879d8a;
		else
			return 0;
	}
	
	public static int getResultBytesSize() {
		return SM3_OUTPUT_BYTES;
	}
	
	public Boolean Digest(byte[] from, byte[] to) {
		if( null == to || (to.length < this.getResultBytesSize()) )
			return false;
		
		int a, b, c, d, e, f, g, h, ss1, ss2, tt1, tt2;		
		int[] B = paddingMessage(from);
		int[] W0 = new int[132];
		int[] W1 = new int[SM3_A_BLOCK_BYTES];

		log.printIntegersInHEX("after padding, B", B);
		
		int blocks = B.length / SM3_A_BLOCK_WORDS;
		
		int[] V = new int[SM3_V0.length];
		for(int i = 0; i < V.length; ++i)
			V[i] = SM3_V0[i];
		
		for(int i = 0; i < blocks; ++i) {
//			System.err.printf("block %02d\nAfter Expand W0[0~67]:\n", i);
			for(int j = 0; j < SM3_A_BLOCK_WORDS ; ++j) {
				W0[j] = B[i * SM3_A_BLOCK_WORDS + j];
				
//				System.err.printf("%08X ", W0[j]);
//				if( (0 == (j+1) % 8) && (j > 0) )
//					System.err.println();
			}
			for(int j = 16; j < 68; ++j) {
				W0[j] = P1(W0[j - 16] ^ W0[j - 9] ^ Integer.rotateLeft(W0[j - 3], 15)) ^ Integer.rotateLeft(W0[j - 13], 7) ^ W0[j - 6];

//				System.err.printf("%08X ", W0[j]);
//				if( (0 == (j+1) % 8) && (j > 16) )
//					System.err.println();
			}
//			System.err.printf("\nW1[0~63]:\n");
			for(int j = 0; j < 64; ++j) {
				W1[j] = W0[j] ^ W0[j+4];

//				System.err.printf("%08X ", W1[j]);
//				if( (0 == (j+1) % 8) && (j > 0) )
//					System.err.println();
			}
			
//			System.err.printf("\nTemp steps:\n");
			a = V[0];
			b = V[1];
			c = V[2];
			d = V[3];
			e = V[4];
			f = V[5];
			g = V[6];
			h = V[7];
			for(int j = 0; j < 64; ++j) {
				ss1 = Integer.rotateLeft(Integer.rotateLeft(a, 12) + e + Integer.rotateLeft(T(j), j), 7);
				ss2 = ss1 ^ Integer.rotateLeft(a, 12);
				tt1 = FF(j, a, b, c) + d + ss2 + W1[j];
				tt2 = GG(j, e, f, g) + h + ss1 + W0[j];
				d = c;
				c = Integer.rotateLeft(b, 9);
				b = a;
				a = tt1;
				h = g;
				g = Integer.rotateLeft(f, 19);
				f = e;
				e = P0(tt2);
				
//				System.err.printf("t=%02d, a=%08X, b=%08X, c=%08X, d=%08X, e=%08X, f=%08X, g=%08X, h=%08X, W0[%02d]=%08X, W1[%02d]=%08X, SS1=%08X, SS2=%08X, TT1=%08X, TT2=%08X\n", 
//						j, a, b, c, d, e, f, g, h, j, W0[j], j, W1[j], ss1, ss2, tt1, tt2);
			}
			
			V[0] = a ^ V[0];
			V[1] = b ^ V[1];
			V[2] = c ^ V[2];
			V[3] = d ^ V[3];
			V[4] = e ^ V[4];
			V[5] = f ^ V[5];
			V[6] = g ^ V[6];
			V[7] = h ^ V[7];
		}
		
		for(int i = 0; i < V.length; ++i) {
			to[i*4+0] = (byte) ((V[i] & 0x0ff000000) >>> 24);
			to[i*4+1] = (byte) ((V[i] &  0x00ff0000) >>> 16);
			to[i*4+2] = (byte) ((V[i] &  0x0000ff00) >>> 8);
			to[i*4+3] = (byte) ( V[i] &  0x000000ff);
		}
		
		System.err.printf("result: %08X%08X%08X%08X%08X%08X%08X%08X\n\n", V[0],V[1],V[2],V[3],V[4],V[5],V[6],V[7]);
		return true;
	}
}
