package sha;

import tools.LOG;
import tools.TOOLS;

//https://tools.ietf.org/html/rfc6234
//online test: https://emn178.github.io/online-tools/index.html
//online test: https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values

public final class SHA_512 extends SHA_ABS{
	TOOLS tools = TOOLS.getInstance();
	LOG log = LOG.getInstance();
	
	public final int SHA_512_A_BLOCK_WORDS = 16;
	private final int SHA_512_A_BLOCK_BYTES = SHA_512_A_BLOCK_WORDS*8;
	public final int SHA_512_A_BLOCK_BITS = SHA_512_A_BLOCK_BYTES*8;
	
	public final int SHA_512_A_BLOCK_USED_WORDS = SHA_512_A_BLOCK_WORDS-2;
	public final int SHA_512_A_BLOCK_USED_BYTES = SHA_512_A_BLOCK_USED_WORDS*8;
	public final int SHA_512_A_BLOCK_USED_BITS = SHA_512_A_BLOCK_USED_BYTES*8;
	
	public final int SHA_512_MAIN_LOOP_TIMES = 80;
	
	public final int SHA_512_OUTPUT_BYTES = 64;
	
	private static long[] SHA_512_K = { 
         0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL,
         0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L,
         0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
         0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 0xc19bf174cf692694L,
         0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
         0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
         0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L,
         0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL, 0x142929670a0e6e70L,
         0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
         0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL,
         0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L,
         0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
         0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L,
         0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L,
         0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
         0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL,
         0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L,
         0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
         0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL,
         0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L};
//	private final int SHA_512_K_LENS = SHA_512_K.length;

	private static long[] SHA_512_H0 = { 
			0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L, 0x510e527fade682d1L, 0x9b05688c2b3e6c1fL, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L };
	
	private long CH(long x, long y, long z) {
		return (x & y) ^ ((~x) & z);
	}

	private long MAJ(long x, long y, long z) {
		return (x & y) ^ (x & z) ^ (y & z);
	}

	private long BSIG0(long x) {
		return Long.rotateRight(x, 28) ^ Long.rotateRight(x, 34) ^ Long.rotateRight(x, 39);
	}

	private long BSIG1(long x) {		
		return Long.rotateRight(x, 14) ^ Long.rotateRight(x, 18) ^ Long.rotateRight(x, 41);
	}

	private long SSIG0(long x) {
		return Long.rotateRight(x, 1) ^ Long.rotateRight(x, 8) ^ (x >>> 7);
	}

	private long SSIG1(long x) {
		return Long.rotateRight(x, 19) ^ Long.rotateRight(x, 61) ^ (x >>> 6);
	}
	
	private long[] paddingMessage(byte[] from) {
		byte[] to;
		if( null == from || 0 == from.length ) {
			to =  new byte[SHA_512_A_BLOCK_BYTES];
			to[0] = (byte) 0x80;
			
		} else if( from.length < SHA_512_A_BLOCK_USED_BYTES ) {
			to = new byte[SHA_512_A_BLOCK_BYTES];
			tools.copyArray(from, 0, from.length, to, 0);
			to[from.length] = (byte) 0x80;
			tools.longTo16BytesMSB(from.length*8, to, to.length-16);
		
		} else { // from.length >= SHA_512_A_BLOCK_USED_BYTES
			to = new byte[(from.length/SHA_512_A_BLOCK_BYTES+(from.length % SHA_512_A_BLOCK_BYTES < SHA_512_A_BLOCK_USED_BYTES ? 1:2))*SHA_512_A_BLOCK_BYTES];
			tools.copyArray(from, 0, from.length, to, 0);
			if( 0 != from.length % SHA_512_A_BLOCK_BYTES )
				to[from.length] = (byte) 0x80;
			tools.longTo16BytesMSB(from.length*8, to, to.length-16);
		}
		
		long[] tolong = new long[to.length/8];
		
		for(int i = 0; i < tolong.length; ++i) {
			tolong[i] = tolong[i] | ((long)(to[i*8]&0x0ff) << 56);
			tolong[i] = tolong[i] | ((long)(to[i*8+1]&0x0ff) << 48);
			tolong[i] = tolong[i] | ((long)(to[i*8+2]&0x0ff) << 40);
			tolong[i] = tolong[i] | ((long)(to[i*8+3]&0x0ff) << 32);
			tolong[i] = tolong[i] | ((long)(to[i*8+4]&0x0ff) << 24);
			tolong[i] = tolong[i] | ((long)(to[i*8+5]&0x0ff) << 16);
			tolong[i] = tolong[i] | ((long)(to[i*8+6]&0x0ff) << 8);
			tolong[i] = tolong[i] | ((long)to[i*8+7]&0x0ff);
		}
		
		return tolong;
	}
	
	
	public Boolean Digest(byte[] from, byte[] to) {
		long a, b, c, d, e,f, g, h;
		long[] M = paddingMessage(from);
		long[] W = new long[SHA_512_A_BLOCK_BYTES];
		
		log.printLongsInHEX("after padding, M", M);
		
		long blocks = M.length / SHA_512_A_BLOCK_WORDS;
		
		System.err.printf("M blocks = %d\n\n", blocks);
		
		long[] H = new long[SHA_512_H0.length];
		for(int i = 0; i < SHA_512_H0.length; ++i)
			H[i] = SHA_512_H0[i];
		
		System.err.printf("Inital has value:\n");
		for(int t = 0; t < H.length; ++t) {
			System.err.printf("H[%d] = %016X\n", t, H[t]);
		}
		System.err.println();
		
//		for(int i = 0; i < M.length; ++i)
//			System.err.printf("M[%d]=%016X\n", i, M[i]);
		
		for(int i = 0; i < blocks; ++i) {
			for(int t = 0; t < SHA_512_A_BLOCK_WORDS; ++t)
				W[t] = M[i* SHA_512_A_BLOCK_WORDS +t];
			
			for(int t = 16; t < SHA_512_MAIN_LOOP_TIMES; ++t)
				W[t] = SSIG1(W[t-2]) + W[t-7] + SSIG0(W[t-15]) + W[t-16];
			
			a = H[0];
			b = H[1];
			c = H[2];
			d = H[3];
			e = H[4];
			f = H[5];
			g = H[6];
			h = H[7];
			
			long T1, T2;
			for(int t = 0; t < SHA_512_MAIN_LOOP_TIMES; ++t) {
				T1 = h + BSIG1(e) + CH(e, f, g) + SHA_512_K[t] + W[t];
				T2 = BSIG0(a) + MAJ(a, b, c);				
				h = g;
				g = f;
				f = e;
				e = d + T1;
				d = c;
				c = b;
				b = a;
				a = T1 + T2;
				
				System.err.printf("t=%02d, a=%016X, b=%016X, c=%016X, d=%016X, e=%016X, f=%016X, g=%016X, h=%016X, W[%02d]=%016X, T1=%016X, T2=%016X\n", t, a, b, c, d, e, f, g, h, t, W[t], T1, T2);
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
		
		System.err.printf("result: %016X%016X%016X%016X%016X%016X%016X%016X\n\n", H[0],H[1],H[2],H[3],H[4],H[5],H[6],H[7]);
		return true;
	}

	@Override
	int getResultBytesSize() {
		return this.SHA_512_OUTPUT_BYTES;
	}


}

