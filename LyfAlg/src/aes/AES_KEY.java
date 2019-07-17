package aes;

import java.io.UnsupportedEncodingException;

import tools.TOOLS;
import tools.LOG;

//@misc{AES-FIPS, 
//title = "Specification for the Advanced Encryption Standard (AES)", 
//howpublished = "Federal Information Processing Standards Publication 197", 
//year = "2001", 
//url = " http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf" 
//} 

public class AES_KEY {
	private TOOLS tools = TOOLS.getInstance();
	private LOG log = LOG.getInstance();
	private AES_SBOX sbox = AES_SBOX.getInstance();
	
	private final int AES_A_BLOCK_BITS = 128;
	private final int AES_A_BLOCK_BYTES = AES_A_BLOCK_BITS/32;
	
	private final int AES_KEY_128_BITS = 128;
	private final int AES_KEY_192_BITS = 192;
	private final int AES_KEY_256_BITS = 256;
	
	private final int AES_KEY_ROUND_10 = 10;
	private final int AES_KEY_ROUND_12 = 12;
	private final int AES_KEY_ROUND_14 = 14;
	
	private final int AES_KEY_A_WORD_BYTES = 4;
	private final int AES_KEY_A_WORD_BITS = AES_KEY_A_WORD_BYTES*8;
	
	private final byte[][] rcon = {
			{0,0,0,0},
			{0x01, 0, 0, 0},
			{0x02, 0, 0, 0},
			{0x04, 0,0, 0},
			{0x08, 0, 0, 0},
			{0x10, 0, 0, 0},
			{0x20, 0,0, 0},
			{0x40, 0, 0, 0},
			{(byte) 0x80, 0, 0, 0},
			{0x1B, 0,0, 0},
			{0x36, 0, 0, 0}
	};
	
	private byte[] keys;
	
	private final byte[] Nr_table = {AES_KEY_ROUND_10, AES_KEY_ROUND_12, AES_KEY_ROUND_14};
	private int key_bit_count = 128; //default;
	private int Nr = 0;
	private int Nk = 0;
	private final int Nb = 4; //constant
	
	public AES_KEY(String keystr) {
		if( null == keystr || 0 == keystr.length()) {
			initEmptyKey();
			return ;
		}
			
		try {
			byte[] tmp = keystr.getBytes("US-ASCII");
			initKey(tmp);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	}
	
	public AES_KEY(byte[] keys) {
		initKey(keys);
	}
	
	public void initKey(byte[] k) {
		if (k.length <= AES_KEY_128_BITS / 8)
			key_bit_count = AES_KEY_128_BITS;
		else if (k.length > AES_KEY_128_BITS / 8 && k.length <= AES_KEY_192_BITS / 8)
			key_bit_count = AES_KEY_192_BITS;
		else if (k.length > AES_KEY_192_BITS / 8 )
			key_bit_count = AES_KEY_256_BITS;
		else {
			key_bit_count = AES_KEY_256_BITS;
		}
		
		Nr = Nr_table[(key_bit_count-AES_KEY_128_BITS)/(AES_KEY_A_WORD_BITS*2)];

		Nk = key_bit_count/AES_KEY_A_WORD_BITS;
		
		keys = new byte[(Nr+1)*Nb*AES_KEY_A_WORD_BYTES];
		tools.copyArray(k, 0, k.length<=key_bit_count/8?k.length:key_bit_count/8, keys, 0);
	}
	
	public void initEmptyKey() {
		key_bit_count = AES_KEY_128_BITS;
		
		Nr = Nr_table[(key_bit_count-AES_KEY_128_BITS)/(AES_KEY_A_WORD_BITS*2)];
		
		Nk = key_bit_count/AES_KEY_A_WORD_BITS;
		
		keys = new byte[(Nr+1)*Nb*AES_KEY_A_WORD_BYTES];
	}
	
	//from and to can overlap
	private Boolean rotWord(byte[] from, byte[] to) {
		if( null == from || AES_KEY_A_WORD_BYTES != from.length || null == to || AES_KEY_A_WORD_BYTES != to.length ) {
			System.err.println("rotWord(): return false");
			return false;
		}
		
		byte t = from[0];
		to[0] = from[1];
		to[1] = from[2];
		to[2] = from[3];
		to[3] = t;
		
		return true;
	}
	
	public Boolean keyExpansion() {
		if ( AES_KEY_128_BITS != key_bit_count && AES_KEY_192_BITS != key_bit_count && AES_KEY_256_BITS != key_bit_count ) {
			System.err.println("generateSubKeys(): return false");
			return false;
		}

		System.err.printf("generateSubKeys() ==== start ====\n");
		log.printBytesInHEX("original key=", keys, 0, key_bit_count/8 );
		
		int wi = 0;
		int wi_off = 0;
		int wi_Nk_off = 0;
		int wi_1_off = 0;
		
		byte[] temp = new byte[Nb];
		for(wi = Nk; wi < (Nr+1)*Nb; ++wi) {
			wi_off = wi*Nb;
			wi_Nk_off = (wi - Nk)*Nb;
			wi_1_off = (wi - 1)*Nb;
			
			
			tools.copyArray(keys, wi_1_off, Nb, temp, 0);
			
			System.err.printf("wi=%d, temp=%s, ", wi, log.getBytesInHEX(temp));
			
			if( 0 == wi % Nk ) {
				// wi = (wi-nr) ^ subWord(rotWord(wi-1)) ^ rcon[i/Nk]
				
				rotWord(temp, temp);
				System.err.printf("after rotWord=%s, ", log.getBytesInHEX(temp));
				
				sbox.subWord(temp, temp);
				System.err.printf("after subWord=%s, ", log.getBytesInHEX(temp));
				
				System.err.printf("rcon=%s ", log.getBytesInHEX(rcon[wi/Nk]));
				tools.xor(temp, rcon[wi/Nk], temp);
				System.err.printf("after xor with rcon=%s, ", log.getBytesInHEX(temp));
			
			} else if( (Nk > 6) && (4 == wi % Nk) ) {
				//wi = (wi-nr) ^ subWord(wi-1)
				
				sbox.subWord(temp, temp);
				System.err.printf("after subWord=%s, ", log.getBytesInHEX(temp));
			} else {
				//wi = (wi-nk) ^ (wi-1)
			}
			
			System.err.printf("wi-Nk=%s, ", log.getWordInHEX(keys, wi_Nk_off));
			
			keys[wi_off] = (byte) (keys[wi_Nk_off] ^ temp[0]);
			keys[wi_off+1] = (byte) (keys[wi_Nk_off+1] ^ temp[1]);
			keys[wi_off+2] = (byte) (keys[wi_Nk_off+2] ^ temp[2]);
			keys[wi_off+3] = (byte) (keys[wi_Nk_off+3] ^ temp[3]);
			
			System.err.printf("wi=%s\n", log.getWordInHEX(keys, wi_off));
		}
		
		for(wi = 0; wi < (Nr+1)*Nb; ++wi) {
			log.printBytesInHEX("round["+wi+"]", keys, wi*Nb*AES_KEY_A_WORD_BYTES, Nb*AES_KEY_A_WORD_BYTES);
		}
		
		System.err.printf("generateSubKeys() ==== end ====\n");
		
		return true;
	}
	
	//0 ~ 14
	public byte[] getRoundKey(int round) {
		byte[] temprk = new byte[Nb*AES_KEY_A_WORD_BYTES];
		
		if( round < 0 || round > AES_KEY_ROUND_14 ) {
			tools.copyArray(keys, 0, Nb*AES_KEY_A_WORD_BYTES, temprk, 0);
		} else {
			tools.copyArray(keys, round*Nb*AES_KEY_A_WORD_BYTES, Nb*AES_KEY_A_WORD_BYTES, temprk, 0);
		}
		
		return temprk;
	}
	
	public int getNr() {
		return Nr;
	}
}
