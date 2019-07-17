package rsa;

import java.math.BigInteger;

import tools.LOG;

public class testRSAMain {
	private static LOG log = LOG.getInstance();

	private static void testRSA() {
		RSA rsa = new RSA();
		
		String pp = "92D491E86A649F206CD8412E091E38B041020C5DDD9EA79DC9197A150867EC0835B7017F98092664C360A6A18EEE33456337ABF2A965A89641089CDCB509111B19F3F86B56D881962C6CAD12CBFF055E9E5D19CD6753C596AEADC7BDDF1E5DC30093A764C27D14FA9176F7589A41EE9FF51AC1030E2B9691D26735459FD29D0B";
		String qq = "F2A2078E6BABA08012A155C1E1C08211958DCFE78B53311E66F62E029EA2104AB79399E94D7F34D67CAD26E3A64858E9410DEB103291D2D5CF75C4F0036B07C8BF17B57891BF769530B9E442831329F4EE2B68405F1BE7E90EEFC005C9432C97EA558347CECBE974390BD8D3B0DF6F79E322C22A9A2B1AEE8CC1D14CB71EC74B";
		String ee = "10001";
		
//		rsa.GenerateKeys(2048, pp, qq, ee);
//		rsa.GenerateKeys(new BigInteger(pp,16), new BigInteger(qq,16), new BigInteger(ee,16));
		rsa.generateKeys(2048);
		
		String m = "abc";
		System.err.printf("plaintext: %s\n", m);
		byte[] bc = rsa.encrypt(rsa.getPubKey(), m.getBytes());
		log.printBytesInHEX("cryptotext: ", bc);
		byte[] bm = rsa.decrypt(rsa.getPriKey(), bc);
		System.err.printf("after decrypt, plainttext: %s\n", new String(bm));
	}

	public static void testGetD() {
		RSA rsa = new RSA(2048);

		BigInteger fn = new BigInteger("3220");
		BigInteger e = new BigInteger("79");

		BigInteger d = null;
//		d = rsa.getD(fn, e); //should change this private function to public for test

		System.err.printf("fn=%d, e=%d, d=%d\n", fn, e, d);
	}
	
	public static void main(String[] args) {
//		testGetD();
		
		testRSA();
	}

}
