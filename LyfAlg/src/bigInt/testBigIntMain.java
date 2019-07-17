package bigInt;

import java.math.BigInteger;
import java.util.Random;

public class testBigIntMain {

	public static void testBigInt() {
//		Random r = new Random();
//		r.setSeed(1234234L);
//		BigInteger a = BigInteger.probablePrime(64, r);
//		BigInteger b = BigInteger.probablePrime(64, r);
//		BigInteger c = a.multiply(b);
//	
//		System.err.printf("c=%d\n", c.bitLength());
//	
//		////////////////
//		
		byte[] bigint = { 
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
				(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};
		BigInteger aa = new BigInteger(1, bigint);
		BigInteger cc = aa.multiply(aa);
		System.err.printf("aa= %x=\"%s\" %d\n", aa, aa, aa.bitLength());
		aa = aa.add(aa);
		System.err.printf("aa=aa+aa = %x=\"%s\" %d\n", aa, aa, aa.bitLength());
		System.err.printf("cc=aa*aa = %x=\"%s\" %d\n", cc, cc, cc.bitLength());

	}
	
	public static void main(String[] args) {
		testBigInt();
	}
}
