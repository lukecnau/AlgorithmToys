package sm2;

import java.math.BigInteger;

import sm3.SM3;
import tools.LOG;

public class SM2_PRI_KEY extends ECFunction {
	private LOG log = LOG.getInstance();
	private BigInteger d_;
	private SM2_PRI_KEY() {}
	
	public SM2_PRI_KEY(ECFunction ecf, BigInteger d) {
		this.CopyFrom(ecf);
		this.d_ = d;
	}
	
	public byte[] decrypt(byte[] c) {
		int pbitlen = p_.bitLength();
		int pbytes = (0 != pbitlen%8 ? pbitlen/8+1 : pbitlen/8);
		
		byte[] C1Bytes = new byte[pbytes*2+1];
		System.arraycopy(c, 0, C1Bytes, 0, C1Bytes.length);
		
		log.printBytesInHEX("C1", C1Bytes);
		
		ECPoint C1 = this.decoded(C1Bytes);
		
		byte[] C3Bytes = new byte[SM3.getResultBytesSize()];
		System.arraycopy(c, c.length-C3Bytes.length, C3Bytes, 0, C3Bytes.length);

		
		byte[] C2Bytes = new byte[c.length - C1Bytes.length - C3Bytes.length];
		System.arraycopy(c, C1Bytes.length, C2Bytes, 0, C2Bytes.length);
		
		log.printBytesInHEX("C2", C2Bytes);

		log.printBytesInHEX("C3", C3Bytes);

		//check whether C1 is available, here I ingore this step.
		
		ECPoint dbC1 = C1.multiply(d_);
		
		dbC1.showInfo("[dB]C1");
		
		byte[] t = KDF(dbC1.getKDFBytes(), C2Bytes.length*8);

		log.printBytesInHEX("t=KDF( dbC1.x2 || dbC1.y2, klen)", t);
		
		BigInteger C2 = new BigInteger(C2Bytes);
		BigInteger M = C2.xor(new BigInteger(t));
		byte[] retM = M.toByteArray();
		
		log.printBytesInHEX("M'", retM);
		
		byte[] u = Hash(dbC1, M.toByteArray());
		
		log.printBytesInHEX("u", C3Bytes);
		
		if( compareBytes(u, C3Bytes) ) {
			return retM;
		} else {
			return null;
		}
		
	}
	
	private boolean compareBytes(byte[] u, byte[] C3) {
		BigInteger bu = new BigInteger(u);
		BigInteger bc3 = new BigInteger(C3);
		
		if( 0 != bu.xor(bc3).compareTo(BigInteger.ZERO) )
			return false;
		else
			return true;
		
	}
}
