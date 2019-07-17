package sm4;

public class SM4_KEY {
	private SM4_SBOX sbox = SM4_SBOX.getInstance();
	
	private final int[] FK = {0x0a3b1bac6, 0x056aa3350, 0x0677d9197, 0x0b27022dc};
	private final int [] CK = {
		0x000070e15, 0x01c232a31, 0x0383f464d, 0x0545b6269, 
		0x070777e85, 0x08c939aa1, 0x0a8afb6bd, 0x0c4cbd2d9, 
		0x0e0e7eef5, 0x0fc030a11, 0x0181f262d, 0x0343b4249, 
		0x050575e65, 0x06c737a81, 0x0888f969d, 0x0a4abb2b9, 
		0x0c0c7ced5, 0x0dce3eaf1, 0x0f8ff060d, 0x0141b2229, 
		0x030373e45, 0x04c535a61, 0x0686f767d, 0x0848b9299, 
		0x0a0a7aeb5, 0x0bcc3cad1, 0x0d8dfe6ed, 0x0f4fb0209, 
		0x010171e25, 0x02c333a41, 0x0484f565d, 0x0646b7279
	};
	private final int SM4_KEY_COUNT = 32;
	private final int SM4_KEY_INTS = 4;
	
	private int[] mk = {0,0,0,0};
	private int[] rk = new int[SM4_KEY_COUNT];

	public SM4_KEY(int[] key) {
		initKey(key);
	}
	
	private void initKey(int[] key) {
		if( null == key || SM4_KEY_INTS != key.length )
			return ;
		
		mk[0] = key[0];
		mk[1] = key[1];
		mk[2] = key[2];
		mk[3] = key[3];
	}
	
	public Boolean KeyExpansion() {
		int[] k = new int[SM4_KEY_INTS];
		
		k[0] = mk[0]^FK[0];
		k[1] = mk[1]^FK[1];
		k[2] = mk[2]^FK[2];
		k[3] = mk[3]^FK[3];
		
		for(int i = 0; i<SM4_KEY_COUNT; ++i) {
			System.err.printf("k[%d] = %08x, k[%d] = %08x, k[%d] = %08x, k[%d] = %08x, ", i, k[i%4], i+1, k[(i+1)%4], i+2, k[(i+2)%4], i+3, k[(i+3)%4]);

			k[i%4] = k[i%4] ^ sbox.t1(k[(i+1)%4] ^ k[(i+2)%4] ^ k[(i+3)%4] ^ CK[i]);
			rk[i] = k[i%4];
			
			System.err.printf("| after: lastK = %08x, rk[%2d] = %08x\n", k[i%4], i, rk[i]);
		}
		
		return true;
	}
	
	public int getRoundKey(int round) {
		if( round < 0 || round > SM4_KEY_COUNT ) {
			return 0;
		} else {
			return rk[round];
		}
	}
}
