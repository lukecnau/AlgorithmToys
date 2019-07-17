package sm2;

import java.math.BigInteger;
import java.util.ArrayList;

import sm3.SM3;
import tools.LOG;

public class SM2_PUB_KEY extends ECFunction {
	ECPoint P_;
	LOG log = LOG.getInstance();
	
	private SM2_PUB_KEY() {}
	
	public SM2_PUB_KEY(ECFunction ecf, ECPoint p) {
		this.CopyFrom(ecf);
		P_ = p;
	}
	
	public byte[] encrypt(byte[] m, byte[] k) {
		BigInteger K = new BigInteger(1, k);
		BigInteger M = new BigInteger(1, m);
	
		ECPoint C1 = this.G_.multiply(K);
		
		C1.showInfo("C1");
		
		ECPoint kPb = this.P_.multiply(K);
		
		kPb.showInfo("[k]PB");
		
		byte[] t = KDF(kPb.getKDFBytes(), m.length*8);
		
		log.printBytesInHEX("t = KDF(kPB.x2 || kPB.y2, klen)", t);
		
// another way to get C2
//		byte[] C2 = new byte[t.length];
//		tools.xor(M.toByteArray(), t, C2);
//		log.printBytesInHEX("C2", C2);
		BigInteger C2 = M.xor(new BigInteger(t));
		log.printBytesInHEX("C2", C2.toByteArray());
		
		byte[] C3 = Hash(kPb, m);
		
		log.printBytesInHEX("C3", C3);
		
		byte[] C1Bytes = this.encoded(C1);
		byte[] C2Bytes = C2.toByteArray();
		byte[] C = new byte[C1Bytes.length + C2Bytes.length + C3.length];
		System.arraycopy(C1Bytes, 0, C, 0, C1Bytes.length);
		System.arraycopy(C2Bytes, 0, C, C1Bytes.length, C2Bytes.length);
		System.arraycopy(C3, 0, C, C1Bytes.length+C2Bytes.length, C3.length);
		
		log.printBytesInHEX("C = C1 || C2 || C3", C);
		
		return C;
	}
}
