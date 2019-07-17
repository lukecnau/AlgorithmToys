package sm4;

public class SM4 {
	private final int SM4_A_BLOCK_INTS = 4;
	private final int SM4_ROUNDS_COUNT = 32;
	private SM4_SBOX sbox = SM4_SBOX.getInstance();
	private SM4_KEY keys;
	
	public Boolean Cipher(int[] from, SM4_KEY key, int[] to) {
		if( null == from || null == key || null == to || SM4_A_BLOCK_INTS != from.length || SM4_A_BLOCK_INTS != to.length) {
			System.err.println("Cipher(): return false");
			return false;
		}
		
//		System.err.printf("SM4 Cipher() ==== start ====\n");
		if( keys != key)
			keys = key;
		
		int[] x = new int[SM4_A_BLOCK_INTS];
		
		x[0] = from[0];
		x[1] = from[1];
		x[2] = from[2];
		x[3] = from[3];
		
		for (int i = 0; i < SM4_ROUNDS_COUNT; ++i) {

//			System.err.printf("x[%d] = %08x, x[%d] = %08x, x[%d] = %08x, x[%d] = %08x, ", i, x[i % 4], i + 1,
//					x[(i + 1) % 4], i + 2, x[(i + 2) % 4], i + 3, x[(i + 3) % 4]);

			x[i % 4] = x[i % 4] ^ sbox.t(x[(i + 1) % 4] ^ x[(i + 2) % 4] ^ x[(i + 3) % 4] ^ keys.getRoundKey(i));

//			System.err.printf("| after round[%d] crypt: = %08x\n", i, x[i % 4]);
		}
		
		to[0] = x[3];
		to[1] = x[2];
		to[2] = x[1];
		to[3] = x[0];
		
//		System.err.printf("Final result: = 0x%08x 0x%08x 0x%08x 0x%08x\n", to[0], to[1], to[2], to[3]);
//		System.err.printf("SM4 Cipher() ==== end ====\n");
		
		return true;
	}
	
	//same as cipher
	public Boolean InvCipher(int[] from, SM4_KEY key, int[] to) {
		if( null == from || null == key || null == to || SM4_A_BLOCK_INTS != from.length || SM4_A_BLOCK_INTS != to.length) {
			System.err.println("InvCipher(): return false");
			return false;
		}
		
		System.err.printf("SM4 InvCipher() ==== start ====\n");
		if( keys != key)
			keys = key;
		
		int[] x = new int[SM4_A_BLOCK_INTS];
		
		x[0] = from[0];
		x[1] = from[1];
		x[2] = from[2];
		x[3] = from[3];
		
		for (int i = 0; i < SM4_ROUNDS_COUNT; ++i) {

			System.err.printf("x[%d] = %08x, x[%d] = %08x, x[%d] = %08x, x[%d] = %08x, ", i, x[i % 4], i + 1,
					x[(i + 1) % 4], i + 2, x[(i + 2) % 4], i + 3, x[(i + 3) % 4]);

			x[i % 4] = x[i % 4] ^ sbox.t(x[(i + 1) % 4] ^ x[(i + 2) % 4] ^ x[(i + 3) % 4] ^ keys.getRoundKey(SM4_ROUNDS_COUNT-i-1));

			System.err.printf("| after round[%d] crypt: = %08x\n", i, x[i % 4]);
		}
		
		to[0] = x[3];
		to[1] = x[2];
		to[2] = x[1];
		to[3] = x[0];
		
		System.err.printf("Final result: = 0x%08x 0x%08x 0x%08x 0x%08x\n", to[0], to[1], to[2], to[3]);
		System.err.printf("SM4 InvCipher() ==== end ====\n");
		
		return true;
	}
}
