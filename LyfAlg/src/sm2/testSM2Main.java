package sm2;

import java.math.BigInteger;

import tools.TOOLS;

public class testSM2Main {
	static TOOLS tools = TOOLS.getInstance();
	
	private static byte[] userAEncrypt(SM2_PUB_KEY pubkey) {
		System.err.println("\n\n=============== User A encrypt ====================");
		
		String M = "encryption standard";
		System.err.printf("User A encrypts a message is \"%s\".\n", M);
		BigInteger K = new BigInteger("4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F", 16);
		return pubkey.encrypt(M.getBytes(), K.toByteArray());
	}

	private static void userBGenerateKeyPair(SM2 sm2) {
		System.err.println("\n\n=============== User B generate Key Pair ====================");
		//private key
		BigInteger D = new BigInteger("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0", 16);
		
		sm2.generateKeyPair(D);
	}
	
	private static void userBDecrypt(SM2_PRI_KEY prikey, byte[] c) {
		System.err.println("\n\n=============== User B decrypt ====================");
		byte[] m = prikey.decrypt(c);
		if( null == m )
			System.err.println("Sorry, User B got a broken message!");
		else
			System.err.printf("Great! User B got a message is \"%s\"\n", new String(m));
	}
	
	private static void testSM2() {
		BigInteger P = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3", 16);
		BigInteger A = new BigInteger("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498", 16);
		BigInteger B = new BigInteger("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A", 16);
		BigInteger Xg = new BigInteger("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D", 16);
		BigInteger Yg = new BigInteger("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2", 16);
		BigInteger N = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7", 16);
		
		SM2 sm2 = new SM2(Xg, Yg, A, B, P, N);

		userBGenerateKeyPair(sm2);

		byte[] ciphertext = userAEncrypt(sm2.getPubKey());
		
		userBDecrypt(sm2.getPriKey(), ciphertext);
	}
	
	private static void testECPoint() {
		ECFunction f = new ECFunction(1, BigInteger.valueOf(4), BigInteger.valueOf(4), BigInteger.valueOf(5), BigInteger.ZERO, BigInteger.valueOf(0), BigInteger.valueOf(0));
		ECPoint p = new ECPoint(f, BigInteger.valueOf(1), BigInteger.valueOf(2));
		ECPoint q = new ECPoint(f, BigInteger.valueOf(4), BigInteger.valueOf(3));
		
//		ECPoint p = new ECPoint(1, BigInteger.valueOf(3), BigInteger.valueOf(10));
//		ECPoint q = new ECPoint(1, BigInteger.valueOf(13), BigInteger.valueOf(16));

		ECPoint r = p.add(q);

		p.showInfo("p");
		q.showInfo("q");
		r.showInfo("p+q");
		
		
		BigInteger P =  new BigInteger("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3", 16);
		BigInteger A =  new BigInteger("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498", 16);
		BigInteger B =  new BigInteger("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A", 16);
		BigInteger Xg = new BigInteger("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D", 16);
		BigInteger Yg = new BigInteger("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2", 16);
		BigInteger Ng = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7", 16);
		f = new ECFunction(1, A, B, P, Ng, Xg, Yg);
				
		f.showInfo("ECFunction");
		
		BigInteger d =  new BigInteger("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0", 16);
		r = f.G_.multiply(d);
		r.showInfo("P");
	}
	
	
	private static void testBigInteger() {
		BigInteger a,b,p;
		
		p = new BigInteger("5");
		
		a = new BigInteger("80", 16);
		for(int i = 0; i < a.bitLength(); ++i)
			System.err.printf("%d, %s\n", i, a.testBit(i));
		
		a = new BigInteger("-8");
		System.err.printf("%d\n", a.mod(BigInteger.valueOf(5)));
		
		a = new BigInteger("1");
		b = new BigInteger("3");
		System.err.printf("%d\n", b.modInverse(p));
		
		p = new BigInteger("FF", 16);
		int bytelength = p.toString(16).length();
		int bl = p.toByteArray().length;
		int bytelen = (0 != p.bitLength()%8 ? p.bitLength()/8+1 : p.bitLength()/8) ;
		
		System.err.printf("log2q = B%S, 0X%S, bitlength = %d, bytelength = %d, bitl=%d\n", p.toString(2), p.toString(16), bl, bytelength, bytelen);
	}
	
	public static void main(String[] args) {
		testSM2();
		
//		testECPoint();
		
//		testBigInteger();
	}

}
