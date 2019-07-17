package sm2;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;

import sm3.SM3;
import tools.LOG;
import tools.TOOLS;

public class SM2 {
	private TOOLS tools = TOOLS.getInstance();
	private LOG log = LOG.getInstance();
	private ECFunction ECF;
	SM2_PRI_KEY pri;
	SM2_PUB_KEY pub;
	
	private SM2() {}
	
	public SM2(BigInteger xg, BigInteger yg, BigInteger a, BigInteger b, BigInteger p, BigInteger n) {
		init(xg, yg, a, b, p, n);
	}
	
	public void init(BigInteger xg, BigInteger yg, BigInteger a, BigInteger b, BigInteger p, BigInteger n) {		
		ECF = new ECFunction(0x04, a, b, p, n, xg, yg);
	}
	
	public void generateKeyPair(BigInteger d) {
		ECPoint P_ = ECF.G_.multiply(d);
		
		P_.showInfo("P");
		
		pub = new SM2_PUB_KEY(ECF, P_);
		pri = new SM2_PRI_KEY(ECF, d);
	}
	
	public SM2_PRI_KEY getPriKey() {
		return pri;
	}
	
	public SM2_PUB_KEY getPubKey() {
		return pub;
	}
}
