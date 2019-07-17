package rsa;

import java.math.BigInteger;

public class RSA_KEY {
	private BigInteger n_, key_;
	
	private RSA_KEY() {}
	
	public RSA_KEY(BigInteger n, BigInteger key) {
		n_ = n;
		key_ = key;
	}
	
	public BigInteger getKey() {return key_;}
	public BigInteger getN() {return n_;}
}
