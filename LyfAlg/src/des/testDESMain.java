package des;

import tools.LOG;

public class testDESMain {
	private static LOG log = LOG.getInstance();
	
	private static void change(byte[] s) {
		s[0] = 1;
	}
	
	private static void change(Byte s) {
		s = 1;
	}
	
	public static void main(String[] args) {
//		{
//		DES_KEY key = new DES_KEY("BobAlice");
//
////		key.generateSubKeys();
//			byte[] v = { 0x12, 0x34 };
//
//			Log.printBytesInBinary("before", v);
//
//			key.rotateLeftNBits(v, 16, 3);
//
//			Log.printBytesInBinary("after ", v);
//		}

		{
//			byte[] k = {0x01,0x23,0x45,0x67,(byte) 0x89,(byte) 0xAB,(byte) 0xCD,(byte) 0xEF};
//			byte[] k = {0x13,0x34,0x57,0x79,(byte) 0x9B,(byte) 0xBC,(byte) 0xDF,(byte) 0xF1};
			byte[] k = {0x0E, 0x32, (byte) 0x92, 0x32, (byte) 0xEA, 0x6D, 0x0D, 0x73};
			
			DES_KEY key = new DES_KEY(k);
			key.generateSubKeys();
			DES d = new DES();
			
//			d.Encryption("12345678".getBytes(), key, ret);
			byte[] plaintext = { (byte) 0x87,(byte) 0x87,(byte) 0x87,(byte) 0x87,(byte) 0x87,(byte) 0x87,(byte) 0x87,(byte) 0x87 };
//			byte[] plaintext = {0x01,0x23,0x45,0x67,(byte) 0x89,(byte) 0xAB,(byte) 0xCD,(byte) 0xEF};
			byte[] ret1 = new byte[d.DES_CIPHERTEXT_A_BLOCK_BYTES];
			d.Cipher(plaintext, key, ret1) ;
			log.printBytesInHEX("after DES.Encryption()", ret1);
			
			System.err.println();
			
			byte[] ret2 = new byte[d.DES_PLAINTEXT_A_BLOCK_BYTES];
			d.Decryption(ret1, key, ret2);
			log.printBytesInHEX("after DES.Decryption()", ret2);
		}

//		{
//		byte[] from = {1, 2, 3, 4, 5, 6, 7, 8};
//		byte[] to = {0,0,0,0,0,0,0,0};
//		byte[] l = new byte[4];
//		byte[] r = new byte[4];
//
//		d.IP(from, l, r);
//		Log.printBytesInBinary("from", from);
//		Log.printBytesInBinary("l", l);
//		Log.printBytesInBinary("r", r);
//		d.inverseIP(l, r, to);
//		Log.printBytesInBinary("to", to);
//		byte[] frombits = new byte[from.length*8];
//		d.bytes2Bits(from, 0, from.length*8, frombits, 0);
//		Log.printBytesInBinary("from", from);
//		Log.printBytesInDEC("frombits", frombits);
//		d.bits2Bytes(frombits, 0, frombits.length/2, l, 0);
//		Log.printBytesInBinary("l", l);
//		d.bits2Bytes(frombits, frombits.length/2, frombits.length/2, r, 0);
//		Log.printBytesInBinary("r", r);
//		}
		
//		{
//			byte[] a = {8};
//			System.err.printf("a = %d\n",a[0]);
//			change(a);
//			System.err.printf("a after change = %d\n",a[0]);
//			
//			Byte b = 8;
//			System.err.printf("b = %d\n",b);
//			change(b);
//			System.err.printf("b after change = %d\n",b);
//		}

//		{
//			TOOLS a = TOOLS.getInstance();
//			
//			byte[] from = {0x12, 0x74};
//			
//			byte[] to = {0};
//			
//			Log.printBytesInBinary("from ", from);
//			a.leftShiftNBits(from, 3, 4, to);
//			Log.printBytesInBinary("to ", to);
//		}
	}
}