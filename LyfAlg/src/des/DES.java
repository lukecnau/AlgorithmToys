package des;

import tools.TOOLS;
import tools.LOG;

public class DES {
	private TOOLS tools = TOOLS.getInstance();
	private DES_SOE soe = DES_SOE.getInstance();
	private DES_SBOX sbox = DES_SBOX.getInstance();
	private DES_POP pop = DES_POP.getInstance();
	private DES_IP ip = DES_IP.getInstance();
	private DES_INVERSE_IP iip = DES_INVERSE_IP.getInstance();
	private LOG log = LOG.getInstance();
	
	public final int DES_A_BLOCK_BYTES = 8;
	public final int DES_CIPHERTEXT_A_BLOCK_BYTES = 8;
	public final int DES_CIPHERTEXT_A_BLOCK_BITS = DES_CIPHERTEXT_A_BLOCK_BYTES*8;
	public final int DES_PLAINTEXT_A_BLOCK_BYTES = 8;
	public final int DES_PLAINTEXT_A_BLOCK_BITS = DES_PLAINTEXT_A_BLOCK_BYTES*8;

	private DES_KEY keys;
	
	private Boolean f(byte[] from, byte[] k, byte[] to) {
		if( null == from || 0 == from.length || null == k || 0 == k.length || null == to || 0 == to.length ||
				from.length != DES_PLAINTEXT_A_BLOCK_BYTES/2 || k.length != keys.DES_SUBKEY_BYTES ||
			to.length != DES_PLAINTEXT_A_BLOCK_BYTES/2 ) {
			System.err.println("f(): return false");
			return false;
		}

		System.err.println("f() ==== begin ====");
		
		//1. soe
		byte[] expandv = new byte[soe.DES_SOE_RESULT_BITS/8];
		if( !soe.exec(from, expandv) )
			return false;
		
		//2. xor expandv(48 bits) with key(48 bits)
		byte[] afterxor = new byte[soe.DES_SOE_RESULT_BITS/8];
		if( !tools.xor(expandv, k, afterxor) )
			return false;
		
		//3. sbox
		byte[] aftersbox = new byte[sbox.DES_SBOX_RESULT_BITS/8];
		if( !sbox.exec(afterxor, aftersbox) )
			return false;
		
		//4. pop
		if( !pop.exec(aftersbox, to) )
			return false;
		log.printBytesInHEX("f().POP().to", to);
		
		System.err.println("f() ==== end ====");
		return true;
	}
	
	public Boolean Cipher(byte[] from, DES_KEY key, byte[] to) {
		if( null == from || null == key || null == to || 
				DES_A_BLOCK_BYTES != to.length || DES_A_BLOCK_BYTES != from.length ) {
			System.err.println("Cipher(): return false");
			return false;
		}
		
		byte[] left = {0,0,0,0};
		byte[] right = {0,0,0,0};
		
		System.err.printf("DES Encryption() ==== start ====\n");
		//1. generate keys
		if( keys != key)
			keys = key;
		
		System.err.println(" Encryption.IP() ==== start ====");
		//2.3. ip and split to left and right
		if( !ip.exec(from, left, right) )
			return false;
		
		//4.5. encrypt
		for(int i = 0; i < keys.DES_SUBKEY_COUNT; ++i) {
			System.err.printf(" Encryption.f(key %d) ==== start ====\n", i);
			byte[] afterf = new byte[right.length];
			if( !f(right, keys.getSubkey(i), afterf) )
				return false;
			
			System.err.printf(" Encryption.xor() ==== start ====\n");
			byte[] afterxor = new byte[left.length];
			if( !tools.xor(left, afterf, afterxor))
				return false;
			
			System.err.printf(" Encryption.exchange left and right ==== start ====\n");
			if( !tools.copyArray(right, 0, right.length, left, 0) ) return false;
			if( !tools.copyArray(afterxor, 0, afterxor.length, right, 0) ) return false;
		}
		
		System.err.printf(" Encryption.inverseIP ==== start ====\n");
		//6.7. inverse ip
		if( !iip.exec(right, left, to))
			return false;
		
		System.err.printf("DES Encryption() ==== end ====\n");
		return true;
	}
	
	public Boolean Encryption(byte[] from, DES_KEY key, byte[] to) {
		return false;
	}
	
	//same as cipher
	public Boolean InvCipher(byte[] ciphertext, DES_KEY key, byte[] to) {
		byte[] left = {0,0,0,0};
		byte[] right = {0,0,0,0};
		
		System.err.printf("DES Decryption() ==== start ====\n");
		//1. generate keys
		if( keys != key)
			keys = key;
		
		System.err.println(" Decryption.IP() ==== start ====");
		//2.3. ip and split to left and right
		if( !ip.exec(ciphertext, left, right) )
			return false;
		
		//4.5. encrypt
		for(int i = 0; i < keys.DES_SUBKEY_COUNT; ++i) {
			System.err.printf(" Decryption.f(key %d) ==== start ====\n", keys.DES_SUBKEY_COUNT-i);
			byte[] afterf = new byte[right.length];
			if( !f(right, keys.getSubkey(keys.DES_SUBKEY_COUNT-i-1), afterf) )
				return false;
			
			System.err.printf(" Decryption.xor() ==== start ====\n");
			byte[] afterxor = new byte[left.length];
			if( !tools.xor(left, afterf, afterxor))
				return false;
			
			System.err.printf(" Decryption.exchange left and right ==== start ====\n");
			if( !tools.copyArray(right, 0, right.length, left, 0) ) return false;
			if( !tools.copyArray(afterxor, 0, afterxor.length, right, 0) ) return false;
		}
		
		System.err.printf(" Decryption.inverseIP ==== start ====\n");
		//6.7. inverse ip
		if( !iip.exec(right, left, to))
			return false;
		
		System.err.printf("DES Decryption() ==== end ====\n");
		return true;
	}
	
	public Boolean Decryption(byte[] ciphertext, DES_KEY key, byte[] to) {
		return false;
	}
	
}
