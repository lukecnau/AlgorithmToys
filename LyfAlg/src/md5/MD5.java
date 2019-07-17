package md5;

import tools.LOG;
import tools.TOOLS;

//
// RFC 1321
//

public class MD5 {
	private TOOLS tools = TOOLS.getInstance();
	private LOG log = LOG.getInstance();
	
	public final int MD5_OUTPUT_BYTES = 16;
	public final int MD5_A_BLOCK_BITS = 512;
	public final int MD5_A_BLOCK_BYTES = MD5_A_BLOCK_BITS/8;
	public final int MD5_A_BLOCK_WORDS = MD5_A_BLOCK_BITS/32;
	public final int MD5_A_BLOCK_USED_BITS = MD5_A_BLOCK_BITS-64;
	public final int MD5_A_BLOCK_USED_BYTES = MD5_A_BLOCK_USED_BITS/8;

	private final int[][] s = {{7,12,17,22},{5,9,14,20}, {4,11,16,23}, {6,10,15,21}};
	
	// change the High-order first to Low-order first
	private Boolean fillABlock(byte[] from, int fromstart, int len, int[] to) {
		if (null == from || null == to || from.length - fromstart < 0 || 0 == to.length
				|| MD5_A_BLOCK_WORDS != to.length) {
			System.err.println("fillABlock(): args error !");
			return false;
		}

		byte[] tmpfrom = new byte[MD5_A_BLOCK_BYTES];

		tools.zeroArray(to);

		for (int i = 0; i < len; ++i) {
			to[i / 4] = to[i / 4] | (from[i + fromstart] << (i % 4) * 8);
//			System.err.printf("from=0x%08x, to[%d]=0x%08x\n", (from[i+fromstart] << (3-i%4)*8), i/4, to[i/4]);
		}

		// if 0 == len then if from.length == 0 then append padding bits else append length
		// if MD5_A_BLOCK_BYTES == len then do nothing
		// if 0 < len < 56 then append padding bits and append length
		// if MD5_A_BLOCK_USED_BYTES <= len < MD5_A_BLOCK_BYTES then just append padding bits, appending-length will be appended at next time
		if (0 == len) {
			if (0 == from.length)
				to[len / 4] = to[len / 4] | (0x80 << (len % 4) * 8);
			else {
				// write length (in bits) to the last 64 bits
				to[to.length - 2] = to[to.length - 2] | (from.length * 8 & 0x000000ff << 24);
				to[to.length - 2] = to[to.length - 2] | (from.length * 8 & 0x0000ff00 << 8);
				to[to.length - 2] = to[to.length - 2] | (from.length * 8 & 0x00ff0000 >> 8);
				to[to.length - 2] = to[to.length - 2] | (from.length * 8 & 0x0ff000000 >>> 24);
			}
		} else if (MD5_A_BLOCK_BYTES == len) {

		} else if ((len > 0) && (len < MD5_A_BLOCK_USED_BYTES)) {
			to[len / 4] = to[len / 4] | (0x80 << (len % 4) * 8);

			// write length (in bits) to the last 64 bits
			to[to.length - 2] = to[to.length - 2] | (from.length * 8 & 0x000000ff << 24);
			to[to.length - 2] = to[to.length - 2] | (from.length * 8 & 0x0000ff00 << 8);
			to[to.length - 2] = to[to.length - 2] | (from.length * 8 & 0x00ff0000 >> 8);
			to[to.length - 2] = to[to.length - 2] | (from.length * 8 & 0x0ff000000 >>> 24);
		} else if ((len >= MD5_A_BLOCK_USED_BYTES) && (len < MD5_A_BLOCK_BYTES)) {
			to[len / 4] = to[len / 4] | (0x80 << (len % 4) * 8);
		} else
			return false;

//		log.printIntegersInHEX("after expansion", to);

		return true;
	}
	
	private int F(int X, int Y, int Z) {
		return (X & Y) | (~X & Z);
	}

	private int FF(int a, int b, int c, int d, int M, int s, int ti) {
		return b + Integer.rotateLeft(a + (F(b, c, d) + M + ti), s);
	}

	private int H(int X, int Y, int Z) {
		return X ^ Y ^ Z;
	}

	private int HH(int a, int b, int c, int d, int M, int s, int ti) {
		return b + Integer.rotateLeft(a + (H(b, c, d) + M + ti), s);
	}

	private int I(int X, int Y, int Z) {
		return Y ^ (X | ~Z);
	}

	private int II(int a, int b, int c, int d, int M, int s, int ti) {
		return b + Integer.rotateLeft(a + (I(b, c, d) + M + ti), s);
	}

	private int G(int X, int Y, int Z) {
		return (X & Z) | (Y & ~Z);
	}

	private int GG(int a, int b, int c, int d, int M, int s, int ti) {
		return b + Integer.rotateLeft(a + (G(b, c, d) + M + ti), s);
	}

	public int T(int i) {
		long tmp = 4294967296L;
		
		tmp = (long) (tmp * Math.abs(Math.sin(i)));
		
		return (int) tmp;
		
	}

	public Boolean Digest(byte[] from, byte[] to) {
		if (null == from || null == to || 0 == to.length) {
			System.err.println("MD5 Digest(): args error !");
			return false;
		}

		log.printBytesInHEX("orginal data", from);

		//low-order first
		int[] ABCD = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
		int[] abcd = new int[ABCD.length];

		int[] tmpfrom = new int[MD5_A_BLOCK_WORDS];
		int len = 0;
		int fromstart = 0;
		while(true) 
		{
			tools.copyArray(ABCD, 0, 4, abcd, 0);
			
			if( from.length-fromstart > MD5_A_BLOCK_BYTES )
				len = MD5_A_BLOCK_BYTES;
			else
				len = from.length-fromstart;
			
			tools.zeroArray(tmpfrom);
			fillABlock(from, fromstart, len, tmpfrom);

//			System.err.printf("fromstart=%d, from.length=%d\n", fromstart, from.length);
			
			// round 1
			for (int i = 0; i < 16; ++i) {
//				 System.err.printf("before FF( a=0x%08x, b=0x%08x, c=0x%08x, d=0x%08x,
//				 M%d=0x%08x, s=%d, t=0x%08x )\n", abcd[(i*3)%abcd.length],
//				 abcd[(i*3+1)%abcd.length], abcd[(i*3+2)%abcd.length],
//				 abcd[(i*3+3)%abcd.length], i, tmpfrom[i], s[0][i%4], T(i+1));

				abcd[(i * 3) % abcd.length] = FF(abcd[(i * 3) % abcd.length], abcd[(i * 3 + 1) % abcd.length],
						abcd[(i * 3 + 2) % abcd.length], abcd[(i * 3 + 3) % abcd.length], tmpfrom[i], s[0][i % 4],
						T(i + 1));

				System.err.printf("after FF( a=0x%08x, b=0x%08x, c=0x%08x, d=0x%08x, M%d=0x%08x, s=%d, t=0x%08x )\n",
						abcd[(i * 3) % abcd.length], abcd[(i * 3 + 1) % abcd.length], abcd[(i * 3 + 2) % abcd.length],
						abcd[(i * 3 + 3) % abcd.length], i, tmpfrom[i], s[0][i % 4], T(i + 1));
			}

			// round 2
			for (int i = 0; i < 16; ++i) {
//				 System.err.printf("before GG( a=0x%08x, b=0x%08x, c=0x%08x, d=0x%08x,
//				 M%d,s=%d, t=0x%08x )\n", abcd[(i*3)%abcd.length], abcd[(i*3+1)%abcd.length],
//				 abcd[(i*3+2)%abcd.length], abcd[(i*3+3)%abcd.length], (5*i+1)%16, s[1][i%4],
//				 T(i+17));

				abcd[(i * 3) % abcd.length] = GG(abcd[(i * 3) % abcd.length], abcd[(i * 3 + 1) % abcd.length],
						abcd[(i * 3 + 2) % abcd.length], abcd[(i * 3 + 3) % abcd.length], tmpfrom[(5 * i + 1) % 16],
						s[1][i % 4], T(17 + i));

				System.err.printf("after GG( a=0x%08x, b=0x%08x, c=0x%08x, d=0x%08x, M%d,s=%d, t=0x%08x )\n",
						abcd[(i * 3) % abcd.length], abcd[(i * 3 + 1) % abcd.length], abcd[(i * 3 + 2) % abcd.length],
						abcd[(i * 3 + 3) % abcd.length], (5 * i + 1) % 16, s[1][i % 4], T(i + 17));
			}

			// round 3
			for (int i = 0; i < 16; ++i) {
//				 System.err.printf("before HH( a=0x%08x, b=0x%08x, c=0x%08x, d=0x%08x,
//				 M%d,s=%d, t=0x%08x )\n", abcd[(i*3)%abcd.length], abcd[(i*3+1)%abcd.length],
//				 abcd[(i*3+2)%abcd.length], abcd[(i*3+3)%abcd.length], (3*i+5)%16, s[2][i%4],
//				 T(i+33));

				abcd[(i * 3) % abcd.length] = HH(abcd[(i * 3) % abcd.length], abcd[(i * 3 + 1) % abcd.length],
						abcd[(i * 3 + 2) % abcd.length], abcd[(i * 3 + 3) % abcd.length], tmpfrom[(3 * i + 5) % 16],
						s[2][i % 4], T(33 + i));
				System.err.printf("after HH( a=0x%08x, b=0x%08x, c=0x%08x, d=0x%08x, M%d,s=%d, t=0x%08x )\n",
						abcd[(i * 3) % abcd.length], abcd[(i * 3 + 1) % abcd.length], abcd[(i * 3 + 2) % abcd.length],
						abcd[(i * 3 + 3) % abcd.length], (3 * i + 5) % 16, s[2][i % 4], T(i + 33));
			}

			// round 4
			for (int i = 0; i < 16; ++i) {
//				 System.err.printf("before II( a=0x%08x, b=0x%08x, c=0x%08x, d=0x%08x,
//				 M%d,s=%d, t=0x%08x )\n", abcd[(i*3)%abcd.length], abcd[(i*3+1)%abcd.length],
//				 abcd[(i*3+2)%abcd.length], abcd[(i*3+3)%abcd.length], (7*i)%16, s[3][i%4],
//				 T(i+49));

				abcd[(i * 3) % abcd.length] = II(abcd[(i * 3) % abcd.length], abcd[(i * 3 + 1) % abcd.length],
						abcd[(i * 3 + 2) % abcd.length], abcd[(i * 3 + 3) % abcd.length], tmpfrom[(7 * i) % 16],
						s[3][i % 4], T(49 + i));
				System.err.printf("after II( a=0x%08x, b=0x%08x, c=0x%08x, d=0x%08x, M%d,s=%d, t=0x%08x )\n",
						abcd[(i * 3) % abcd.length], abcd[(i * 3 + 1) % abcd.length], abcd[(i * 3 + 2) % abcd.length],
						abcd[(i * 3 + 3) % abcd.length], (7 * i) % 16, s[3][i % 4], T(i + 49));
			}

			ABCD[0] += abcd[0];
			ABCD[1] += abcd[1];
			ABCD[2] += abcd[2];
			ABCD[3] += abcd[3];
			
			if( len >= 0 && len < MD5_A_BLOCK_USED_BYTES)
				break;
			else 
				fromstart += len;
		}
		
		tools.integerTo4BytesLSB(ABCD[0], to, 0);
		tools.integerTo4BytesLSB(ABCD[1], to, 4);
		tools.integerTo4BytesLSB(ABCD[2], to, 8);
		tools.integerTo4BytesLSB(ABCD[3], to, 12);

		log.printBytesInHEX("result =", to);

		return true;
	}
}
