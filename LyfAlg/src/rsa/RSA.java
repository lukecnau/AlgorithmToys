package rsa;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;

public class RSA {
	private BigInteger N, e, d, FN;
	private RSA_KEY pub, pri;
	private int bits_ = 8;
	
	private BigInteger getD(BigInteger fn, BigInteger e) {
		BigInteger n, a;
		ArrayList<BigInteger[]> l = new ArrayList<>();

		n = fn;
		a = e;
		for (int i = 0;; ++i) {
			l.add(n.divideAndRemainder(a));
			System.err.printf("%d, %d/%d = %d ... %d\n", i, n, a, l.get(l.size() - 1)[0], l.get(l.size() - 1)[1]);

			n = a;
			a = l.get(l.size() - 1)[1];
			if (l.get(l.size() - 1)[1].equals(BigInteger.ZERO))
				break;
		}

		System.err.println();

		BigInteger result = new BigInteger("0");
		BigInteger last = new BigInteger("1");
		a = l.get(l.size() - 2)[0];
		for (int i = l.size() - 2; i > 0; --i) {
			BigInteger nexta = l.get(i - 1)[0];
			result = a.multiply(nexta).add(last);
			System.err.printf("%d + %d * %d = %d\n", last, a, nexta, result );
			last = a;
			a = result;
		}

		
		if (0 == l.size() % 2) {
			return fn.subtract(result);
		} else
			return result;
	}

	public RSA() {
	}
	
	public RSA(int bits) {
		bits_ = bits;
		generateKeys(bits);
	}
	
	public void generateKeys(int bits) {
		bits_ = bits;
		Random r = new Random();
		r.setSeed(3^System.currentTimeMillis());
		BigInteger p = BigInteger.probablePrime(bits_/2, r);
		BigInteger q = BigInteger.probablePrime(bits_/2, r);
		N = p.multiply(q);

		System.err.printf("p=%X\n", p);
		System.err.printf("q=%X\n", q);
		System.err.printf("N=%X\n", N);

		FN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

		System.err.printf("FN=%X\n", FN);

		e = BigInteger.valueOf(65537L);

		System.err.printf("e=%X\n", e);

		d = getD(FN, e);

		System.err.printf("d=%X\n", d);

		pub = new RSA_KEY(N, e);
		pri = new RSA_KEY(N, d);
	}
	
	public void GenerateKeys(BigInteger pp, BigInteger qq, BigInteger ee) {
		Random r = new Random();
		BigInteger p = pp;
		BigInteger q = qq;
		N = p.multiply(q);

		bits_ = N.bitLength()+1;
		
		System.err.printf("p=%X\n", p);
		System.err.printf("q=%X\n", q);
		System.err.printf("N=%X\n", N);

		FN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

		System.err.printf("FN=%X\n", FN);

		e = ee;

		System.err.printf("e=%X\n", e);

		BigInteger d = getD(FN, e);

		System.err.printf("d=%X\n", d);

		pub = new RSA_KEY(N, e);
		pri = new RSA_KEY(N, d);
	}
	
	//pp, qq, ee: express as hex string
	public void GenerateKeys(int bits, String pp, String qq, String ee) {
		bits_ = bits;
		Random r = new Random();
		BigInteger p = new BigInteger(pp, 16);
		BigInteger q = new BigInteger(qq, 16);
		N = p.multiply(q);

		System.err.printf("p=%X\n", p);
		System.err.printf("q=%X\n", q);
		System.err.printf("N=%X\n", N);

		FN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

		System.err.printf("FN=%X\n", FN);

		e = new BigInteger(ee, 16);

		System.err.printf("e=%X\n", e);

		BigInteger d = getD(FN, e);

		System.err.printf("d=%X\n", d);

		pub = new RSA_KEY(N, e);
		pri = new RSA_KEY(N, d);
	}
	
	public RSA_KEY getPubKey() {
		return pub;
	}

	public RSA_KEY getPriKey() {
		return pri;
	}
	
	public byte[] encrypt(RSA_KEY key, byte[] m) {
		BigInteger tmpm = new BigInteger(m);
		
		return tmpm.modPow(key.getKey(), key.getN()).toByteArray();
	}
	
	//m should be express as a hex string
//	public String encrypt(RSA_KEY_PAIR key, String m) {
//		BigInteger tmpm = new BigInteger(m.getBytes());
//		
//		return tmpm.modPow(key.getKey(), key.getN()).toString();
//	}
	
	public byte[] decrypt(RSA_KEY key, byte[] m) {
		BigInteger tmpc = new BigInteger(m);
		
		return tmpc.modPow(key.getKey(), key.getN()).toByteArray();
	}
	
//	public String decrypt(RSA_KEY_PAIR key, String c) {
//		BigInteger tmpc = new BigInteger(c);
//		
//		return tmpc.modPow(key.getKey(), key.getN()).toString(16);
//	}
}
