package aes;

import tools.TOOLS;
import tools.LOG;

// @misc{AES-FIPS, 
//	 title = "Specification for the Advanced Encryption Standard (AES)", 
//	howpublished = "Federal Information Processing Standards Publication 197", 
//	year = "2001", 
//	 url = " http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf" 
//	} 
public class AES {
	private LOG log = LOG.getInstance();
	private TOOLS tools = TOOLS.getInstance();
	private AES_SBOX sbox = AES_SBOX.getInstance();
	private AES_INV_SBOX isbox = AES_INV_SBOX.getInstance();
	
	public final int AES_A_BLOCK_BITS = 128;
	public final int AES_A_BLOCK_BYTES = AES_A_BLOCK_BITS/8;
		
	private AES_KEY keys;
	
	//encryption
	private byte xtime(byte v) {
		if (0 != (v & 0x080)) 
			return (byte) ((v << 1) ^ 0x1b);
		else 
			return (byte) (v << 1);
	}
	
	private byte xtime(byte v, int times) {
		byte t = v;
		
		for(int i = 0; i < times; ++i)
			t = xtime(t);
		
		return t;
	}
	
	private Boolean SubBytes(byte[] state) {
		return sbox.subBytes(state, AES_A_BLOCK_BYTES, state);
	}
	
	private Boolean ShiftRows(byte[] state) {
		if( null == state || AES_A_BLOCK_BYTES != state.length ) {
			System.err.println("ShiftRows(): return false");
			return false;
		}
		
		byte [] temp = new byte[4];
		
		for(int i = 1; i < 4; ++i) {
			temp[0] = state[i];
			temp[1] = state[i+4];
			temp[2] = state[i+8];
			temp[3] = state[i+12];
			
			tools.leftShiftNBytes(temp, 0, 4, temp, 0, i);
			
			state[i] = temp[0];
			state[i+4] = temp[1];
			state[i+8] = temp[2];
			state[i+12] = temp[3];
		}
		
		return true;
	}
	
	private Boolean MixColumns(byte[] state) {
		if( null == state || AES_A_BLOCK_BYTES != state.length ) {
			System.err.println("MixColumns(): return false");
			return false;
		}
		
		byte[] temp = new byte[AES_A_BLOCK_BYTES];
		
		for(int i = 0; i < temp.length; i=i+4) {
			temp[i] = (byte) (xtime( (byte) (state[i]^state[i+1]), 1) ^ state[i+1] ^ state[i+2] ^ state[i+3]);
			temp[i+1] = (byte) (xtime( (byte) (state[i+1]^state[i+2]), 1) ^ state[i+2] ^ state[i+3] ^ state[i]);
			temp[i+2] = (byte) (xtime( (byte) (state[i+2]^state[i+3]), 1) ^ state[i+3] ^ state[i] ^ state[i+1]);
			temp[i+3] = (byte) (xtime( (byte) (state[i+3]^state[i]), 1) ^ state[i] ^ state[i+1] ^ state[i+2]);	
		}
		tools.copyArray(temp, 0, temp.length, state, 0);
		
		return false;
	}
	
	private Boolean AddRoundKey(byte[] state, byte[]rk) {
		if( null == state || AES_A_BLOCK_BYTES != state.length || null == rk || AES_A_BLOCK_BYTES != rk.length) {
			System.err.println("AddRoundKey(): return false");
			return false;
		}
		
		for(int i = 0; i < AES_A_BLOCK_BYTES; ++i) {
			state[i] = (byte) (state[i] ^ rk[i]);
		}
		
		return true;
	}
	
	public Boolean Cipher(byte[] from, AES_KEY key, byte[] to) {
		if( null == from || null == key || null == to || 
				AES_A_BLOCK_BYTES != to.length || AES_A_BLOCK_BYTES != from.length ) {
			System.err.println("Cipher(): return false");
			return false;
		}

		if( keys != key)
			keys = key;

		byte[] state = new byte[AES_A_BLOCK_BYTES];
		tools.copyArray(from, 0, AES_A_BLOCK_BYTES, state, 0);

		System.err.printf("Cipher() ==== start ====\n");

		log.printBytesInHEX("round[ 0].input", state, 0, state.length);
		log.printBytesInHEX("round[ 0].k_sch", keys.getRoundKey(0), 0, AES_A_BLOCK_BYTES);
		
		AddRoundKey(state, keys.getRoundKey(0));
		
		for(int i = 0; i < keys.getNr()-1; ++i) {
			log.printBytesInHEX("round[ "+(i+1)+"].start", state, 0, state.length);
			SubBytes(state);
			log.printBytesInHEX("round[ "+(i+1)+"].s_box", state, 0, state.length);
			ShiftRows(state);
			log.printBytesInHEX("round[ "+(i+1)+"].s_row", state, 0, state.length);
			MixColumns(state);
			log.printBytesInHEX("round[ "+(i+1)+"].m_col", state, 0, state.length);
			AddRoundKey(state, keys.getRoundKey(i+1));
			log.printBytesInHEX("round[ "+(i+1)+"].k_sch", keys.getRoundKey(i+1), 0, AES_A_BLOCK_BYTES);
		}
		
		log.printBytesInHEX("round["+keys.getNr()+"].start", state, 0, state.length);
		SubBytes(state);
		log.printBytesInHEX("round["+keys.getNr()+"].s_box", state, 0, state.length);
		
		ShiftRows(state);
		log.printBytesInHEX("round["+keys.getNr()+"].s_row", state, 0, state.length);
		
		AddRoundKey(state, keys.getRoundKey(keys.getNr()));
		log.printBytesInHEX("round["+keys.getNr()+"].k_sch", keys.getRoundKey(keys.getNr()), 0, AES_A_BLOCK_BYTES);
		
		tools.copyArray(state, 0, AES_A_BLOCK_BYTES, to, 0);
		
		log.printBytesInHEX("round["+keys.getNr()+"].output", to, 0, to.length);
		
		System.err.printf("Cipher() ==== end ====\n");
		return true;
	}
	
	public Boolean Encryption(byte[] from, byte[] to) {
		//TODO: you can write it by yourself to implment encrypt more 128 bits plaintext.
		return false;
	}
	
	//decryption
	private Boolean InvSubBytes(byte[] state) {
		return isbox.subBytes(state, AES_A_BLOCK_BYTES, state);
	}
	
	private Boolean InvShiftRows(byte[] state) {
		if( null == state || AES_A_BLOCK_BYTES != state.length ) {
			System.err.println("InvShiftRows(): return false");
			return false;
		}
		
		byte [] temp = new byte[4];
		
		for(int i = 1; i < 4; ++i) {
			temp[0] = state[i];
			temp[1] = state[i+4];
			temp[2] = state[i+8];
			temp[3] = state[i+12];
			
			tools.leftShiftNBytes(temp, 0, 4, temp, 0, 4-i);
			
			state[i] = temp[0];
			state[i+4] = temp[1];
			state[i+8] = temp[2];
			state[i+12] = temp[3];
		}
		
		return true;
	}
	
	private Boolean InvMixColumns(byte[] state) {
		if( null == state || AES_A_BLOCK_BYTES != state.length ) {
			System.err.println("InvMixColumns(): return false");
			return false;
		}
		
		byte[] temp = new byte[AES_A_BLOCK_BYTES];
		
		for(int i = 0; i < temp.length; i=i+4) {
			temp[i] = (byte) (xtime( (byte) (state[i]^state[i+1]^state[i+2]^state[i+3]),3) 
					^ xtime( (byte) (state[i]^state[i+2]),2) 
					^ xtime( (byte) (state[i]^state[i+1]),1)
					^ state[i+1] ^ state[i+2] ^ state[i+3]);
			temp[i+1] = (byte) (xtime( (byte) (state[i]^state[i+1]^state[i+2]^state[i+3]),3) 
					^ xtime( (byte) (state[i+1]^state[i+3]),2) 
					^ xtime( (byte) (state[i+1]^state[i+2]),1)
					^ state[i+2] ^ state[i+3] ^ state[i]);
			temp[i+2] = (byte) (xtime( (byte) (state[i]^state[i+1]^state[i+2]^state[i+3]),3)
					^ xtime( (byte) (state[i+2]^state[i]),2) 
					^ xtime( (byte) (state[i+2]^state[i+3]),1)
					^ state[i+3] ^ state[i] ^ state[i+1]);
			temp[i+3] = (byte) (xtime( (byte) (state[i]^state[i+1]^state[i+2]^state[i+3]),3) 
					^ xtime( (byte) (state[i+3]^state[i+1]),2) 
					^ xtime( (byte) (state[i+3]^state[i]),1)
					^ state[i] ^ state[i+1] ^ state[i+2]);	
		}
		tools.copyArray(temp, 0, temp.length, state, 0);
		
		return false;
	}
	
	public Boolean InvCipher(byte[] from, AES_KEY key, byte[] to) {
		if( null == from || null == key || null == to || 
				AES_A_BLOCK_BYTES != to.length || AES_A_BLOCK_BYTES != from.length ) {
			System.err.println("Cipher(): return false");
			return false;
		}

		if( keys != key)
			keys = key;

		byte[] state = new byte[AES_A_BLOCK_BYTES];
		tools.copyArray(from, 0, AES_A_BLOCK_BYTES, state, 0);

		System.err.printf("InvCipher() ==== start ====\n");

		log.printBytesInHEX("round[ 0].iinput", state, 0, state.length);
		log.printBytesInHEX("round[ 0].ik_sch", keys.getRoundKey(keys.getNr()), 0, AES_A_BLOCK_BYTES);
		
		AddRoundKey(state, keys.getRoundKey(keys.getNr()));
		
		for(int i = 0; i < keys.getNr()-1; ++i) {
			log.printBytesInHEX("round[ "+(i+1)+"].istart", state, 0, state.length);
			
			InvShiftRows(state);
			log.printBytesInHEX("round[ "+(i+1)+"].is_row", state, 0, state.length);
			
			InvSubBytes(state);
			log.printBytesInHEX("round[ "+(i+1)+"].is_box", state, 0, state.length);
			
			AddRoundKey(state, keys.getRoundKey(keys.getNr()-1-i));
			log.printBytesInHEX("round[ "+(i+1)+"].ik_sch", keys.getRoundKey(keys.getNr()-1-i), 0, AES_A_BLOCK_BYTES);
			log.printBytesInHEX("round[ "+(i+1)+"].ik_add", state, 0, state.length);
			
			InvMixColumns(state);
		}
		
		log.printBytesInHEX("round["+keys.getNr()+"].istart", state, 0, state.length);

		InvShiftRows(state);
		log.printBytesInHEX("round["+keys.getNr()+"].is_row", state, 0, state.length);
		
		InvSubBytes(state);
		log.printBytesInHEX("round["+keys.getNr()+"].is_box", state, 0, state.length);
				
		AddRoundKey(state, keys.getRoundKey(0));
		log.printBytesInHEX("round["+keys.getNr()+"].ik_sch", keys.getRoundKey(0), 0, AES_A_BLOCK_BYTES);
		
		tools.copyArray(state, 0, AES_A_BLOCK_BYTES, to, 0);
		
		log.printBytesInHEX("round["+keys.getNr()+"].ioutput", to, 0, to.length);
		
		System.err.printf("InvCipher() ==== end ====\n");
		return true;
	}
	
	public Boolean Decryption(byte[] from, byte[] to) {
		
		//TODO: you can write it by yourself to implment decrypt more 128 bits ciphertext.
		return false;
	}
}
