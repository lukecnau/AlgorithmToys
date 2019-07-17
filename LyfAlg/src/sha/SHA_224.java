package sha;

import tools.LOG;
import tools.TOOLS;

// https://tools.ietf.org/html/rfc6234
// online test: https://emn178.github.io/online-tools/index.html
// online test: https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values

public final class SHA_224 extends SHA_ABS{
	TOOLS tools = TOOLS.getInstance();
	LOG log = LOG.getInstance();
	
	public final int SHA_224_A_BLOCK_WORDS = 16;
	private final int SHA_224_A_BLOCK_BYTES = SHA_224_A_BLOCK_WORDS*4;
	public final int SHA_224_A_BLOCK_BITS = SHA_224_A_BLOCK_BYTES*8;
	
	public final int SHA_224_A_BLOCK_USED_WORDS = SHA_224_A_BLOCK_WORDS-2;
	public final int SHA_224_A_BLOCK_USED_BYTES = SHA_224_A_BLOCK_USED_WORDS*4;
	public final int SHA_224_A_BLOCK_USED_BITS = SHA_224_A_BLOCK_USED_BYTES*8;
	
	public final int SHA_224_MAIN_LOOP_TIMES = 64;
	
	public final int SHA_224_OUTPUT_BYTES = 28;
	
	private static int[] SHA_224_K = { 
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };
//	private final int SHA_256_K_LENS = SHA_256_K.length;

	private static int[] SHA_224_H0 = { 
			0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4 };
	
	private int CH(int x, int y, int z) {
		return (x & y) ^ ((~x) & z);
	}

	private int MAJ(int x, int y, int z) {
		return (x & y) ^ (x & z) ^ (y & z);
	}

	private int BSIG0(int x) {
		return Integer.rotateRight(x, 2) ^ Integer.rotateRight(x, 13) ^ Integer.rotateRight(x, 22);
	}

	private int BSIG1(int x) {		
		return Integer.rotateRight(x, 6) ^ Integer.rotateRight(x, 11) ^ Integer.rotateRight(x, 25);
	}

	private int SSIG0(int x) {
		return Integer.rotateRight(x, 7) ^ Integer.rotateRight(x, 18) ^ (x >>> 3);
	}

	private int SSIG1(int x) {
		return Integer.rotateRight(x, 17) ^ Integer.rotateRight(x, 19) ^ (x >>> 10);
	}
	
	private int[] paddingMessage(byte[] from) {
		byte[] to;
		if( null == from || 0 == from.length ) {
			to =  new byte[SHA_224_A_BLOCK_BYTES];
			to[0] = (byte) 0x80;
			
		} else if( from.length < SHA_224_A_BLOCK_USED_BYTES ) {
			to = new byte[SHA_224_A_BLOCK_BYTES];
			tools.copyArray(from, 0, from.length, to, 0);
			to[from.length] = (byte) 0x80;
			tools.longTo8BytesMSB(from.length*8, to, to.length-8);
		
		} else { // from.length >= SHA_224_256_A_BLOCK_USED_BYTES
			to = new byte[(from.length/SHA_224_A_BLOCK_BYTES+(from.length%64 < SHA_224_A_BLOCK_USED_BYTES ? 1:2))*SHA_224_A_BLOCK_BYTES];
			tools.copyArray(from, 0, from.length, to, 0);
			if( 0 != from.length % SHA_224_A_BLOCK_BYTES )
				to[from.length] = (byte) 0x80;
			tools.longTo8BytesMSB(from.length*8, to, to.length-8);
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
	
	
	public Boolean Digest(byte[] from, byte[] to) {
		int a, b, c, d, e,f, g, h;
		int[] M = paddingMessage(from);
		int[] W = new int[SHA_224_A_BLOCK_BYTES];
		
		log.printIntegersInHEX("after padding, M", M);
		
		int blocks = M.length / SHA_224_A_BLOCK_WORDS;
		
		System.err.printf("M blocks = %d\n\n", blocks);
		
		int[] H = new int[SHA_224_H0.length];
		for(int i = 0; i < SHA_224_H0.length; ++i)
			H[i] = SHA_224_H0[i];
		
		System.err.printf("Inital has value:\n");
		for(int t = 0; t < H.length; ++t) {
			System.err.printf("H[%d] = %08X\n", t, H[t]);
		}
		System.err.println();
		
//		for(int i = 0; i < M.length; ++i)
//			System.err.printf("M[%d]=%08X\n", i, M[i]);
		
		for(int i = 0; i < blocks; ++i) {
			for(int t = 0; t < SHA_224_A_BLOCK_WORDS ; ++t)
				W[t] = M[i * SHA_224_A_BLOCK_WORDS +t];
			
			for(int t = 16; t < SHA_224_MAIN_LOOP_TIMES; ++t)
				W[t] = SSIG1(W[t-2]) + W[t-7] + SSIG0(W[t-15]) + W[t-16];
			
			a = H[0];
			b = H[1];
			c = H[2];
			d = H[3];
			e = H[4];
			f = H[5];
			g = H[6];
			h = H[7];
			
			int T1, T2;
			for(int t = 0; t < SHA_224_MAIN_LOOP_TIMES; ++t) {
				T1 = h + BSIG1(e) + CH(e, f, g) + SHA_224_K[t] + W[t];
				T2 = BSIG0(a) + MAJ(a, b, c);
				h = g;
				g = f;
				f = e;
				e = d + T1;
				d = c;
				c = b;
				b = a;
				a = T1 + T2;
				
				System.err.printf("t=%d, a=%08X, b=%08X, c=%08X, d=%08X, e=%08X, f=%08X, g=%08X, h=%08X, W[%d]=%08X, T1=%08X, T2=%08X\n", t, a, b, c, d, e, f, g, h, t, W[t], T1, T2);
			}
			
			H[0] = a + H[0];
			H[1] = b + H[1];
			H[2] = c + H[2];
			H[3] = d + H[3];
			H[4] = e + H[4];
			H[5] = f + H[5];
			H[6] = g + H[6];
			H[7] = h + H[7];
		}
		
		System.err.printf("result: %08X%08X%08X%08X%08X%08X%08X\n\n", H[0],H[1],H[2],H[3],H[4],H[5],H[6]);
		return true;
	}

	@Override
	int getResultBytesSize() {
		return this.SHA_224_OUTPUT_BYTES;
	}


}

