package sm4;

import tools.TOOLS;

public class testSM4Main {
	private static TOOLS tools = TOOLS.getInstance();
	
	public static void testKeyGeneration() {
		int[] key = {0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210};
		
		SM4_KEY k = new SM4_KEY(key);
		
		k.KeyExpansion();
	}
	
	public static void testToolsLeftLoopShiftNbits() {
		int v = Integer.rotateLeft(0x00000001, 31);
		System.err.printf("0x%08x", v);
	}
	
	public static void testEncrypt1() {
		int[] plain = {0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210};
		int[] key = {0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210};
		
		int[] r1 = new int[4];
		
		SM4_KEY k = new SM4_KEY(key);
		
		k.KeyExpansion();
		
		SM4 sm4 = new SM4();
		
		sm4.Cipher(plain, k, r1);
		
		int[] r2 = new int[4];
		sm4.InvCipher(r1, k, r2);
		
	}
	
	public static void testEncrypt2() {
		int[] plain = {0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210};
		int[] key = {0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210};
		
		int[] r1 = new int[4];
		
		SM4_KEY k = new SM4_KEY(key);
		
		k.KeyExpansion();
		
		SM4 sm4 = new SM4();
		
		r1[0] = plain[0];
		r1[1] = plain[1];
		r1[2] = plain[2];
		r1[3] = plain[3];
		
		for(int i = 0; i < 1000000; ++i) {
			sm4.Cipher(r1, k, r1);
		}

		System.err.printf("Final result: = 0x%08x 0x%08x 0x%08x 0x%08x\n", r1[0], r1[1], r1[2], r1[3]);
	}
	
	public static void main(String[] args) {
//		testKeyGeneration();
		
//		testToolsLeftLoopShiftNbits();
		
		testEncrypt1();
		
//		testEncrypt2();
	}

}
