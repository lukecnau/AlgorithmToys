package sm2;

import java.math.BigInteger;
import java.util.ArrayList;

import sm3.SM3;
import tools.LOG;

public class ECFunction {
	private LOG log = LOG.getInstance();
	public BigInteger a_, b_;
	public int PC_;
	public BigInteger p_, nG_;
	public ECPoint G_;
	
	protected ECFunction() {}
	
	public ECFunction(int pc, BigInteger a, BigInteger b, BigInteger p, BigInteger n, BigInteger xg, BigInteger yg) {
		PC_ = pc;
		a_ = a;
		b_ = b;
		p_ = p;
		nG_ = n;
		G_ = new ECPoint(this, xg, yg);
		
		showInfo("EC");
	}
	
	public ECFunction CopyFrom(ECFunction from) {
		this.PC_ = from.PC_;
		this.a_ = from.a_;
		this.b_ = from.b_;
		this.p_ = from.p_;
		this.nG_ = from.nG_;
		this.G_ = from.G_.clone();
		
		return this;
	}
	
	public byte[] encoded(ECPoint p) {
		byte[] r;
		
		//mode: 0x02, compressed; 0x04, uncompressed; 0x06， mixed
		switch (PC_) {
		case 0x02: 
			return new byte[1];
		case 0x04:
			byte[] xbytes = p.x_.toByteArray();
			byte[] ybytes = p.y_.toByteArray();
			
			r = new byte[xbytes.length + ybytes.length + 1];
			r[0] = 0x04;
			
			System.arraycopy(xbytes, 0, r, 1, xbytes.length);
			System.arraycopy(ybytes, 0, r, 1+xbytes.length, ybytes.length);
			return r;
		case 0x06:
			return new byte[1];
		default:
			return new byte[1];
		}
	}
	
	public ECPoint decoded(byte[] c) {
		if( null == c || (0 != (c.length-1)%2) )
			return null;
		
		switch( c[0] ) {
		case 0x02:
			return null;
		case 0x04:
			int bytelen = (c.length-1)/2;
			byte[] xbytes = new byte[bytelen];
			byte[] ybytes = new byte[bytelen];
			System.arraycopy(c, 1, xbytes, 0, bytelen);
			System.arraycopy(c, 1+bytelen, ybytes, 0, bytelen);
			BigInteger x = new BigInteger(1, xbytes);
			BigInteger y = new BigInteger(1, ybytes);
	
			return new ECPoint(this, x, y);
		case 0x06:
			return null;
		default:
			return null;
		}
	}
	
	public byte[] KDF(byte[] Z, int klen) {
		if( null == Z )
			return null;
		
		ArrayList<byte[]> l = new ArrayList<byte[]>();
		
		SM3 sm3 = new SM3();
		
		int len = klen / (sm3.getResultBytesSize()*8);
		if( 0 == len )
			len = 1;
		else if( 0 != (klen / (sm3.getResultBytesSize()*8)) )
			++len;

		byte[] from = new byte[Z.length+4];
		System.arraycopy(Z, 0, from, 0, Z.length);
		for(int i = 0, ct = 1; i < len; ++i, ++ct) {
			from[Z.length+0] = (byte) ((ct & 0x0ff000000) >>> 24);
			from[Z.length+1] = (byte) ((ct &  0x00ff0000) >>> 16);
			from[Z.length+2] = (byte) ((ct &  0x0000ff00) >>> 8);
			from[Z.length+3] = (byte) ( ct &  0x000000ff);
			
			byte[] to = new byte[sm3.getResultBytesSize()];
			sm3.Digest(from, to);
			l.add(to);
		}
		
		int tailLength = (klen - (sm3.getResultBytesSize()*8)*(klen/(sm3.getResultBytesSize()*8)))/8;
		
		byte[] ret = new byte[(l.size()-1)*sm3.getResultBytesSize()+tailLength];
		for(int i = 0; i < l.size(); ++i ) {
			if( (i+1) >= l.size() )
				System.arraycopy(l.get(i), 0, ret, i*sm3.getResultBytesSize(), tailLength);
			else
				System.arraycopy(l.get(i), 0, ret, i*sm3.getResultBytesSize(), sm3.getResultBytesSize());
		}
		
		l.clear();
		
		return ret;
	}
	
	public byte[] Hash(ECPoint kPb, byte[] m) {
		byte[] x2 = kPb.x_.toByteArray();
		byte[] y2 = kPb.y_.toByteArray();
		byte[] x2my2 = new byte[x2.length + m.length + y2.length];
		System.arraycopy(x2, 0, x2my2, 0, x2.length);
		System.arraycopy(m, 0, x2my2, x2.length, m.length);
		System.arraycopy(y2, 0, x2my2, x2.length+m.length, y2.length);

		log.printBytesInHEX("x2 || M || y2", x2my2);
		
		SM3 hash = new SM3();
		
		byte[] C3 = new byte[hash.getResultBytesSize()];
		hash.Digest(x2my2, C3);
		
		return C3;
	}
	
	public void showInfo(String head) {
		System.err.printf("%s.p = %S\n", head, this.p_.toString(16));
		System.err.printf("%s.a = %S\n", head, this.a_.toString(16));
		System.err.printf("%s.b = %S\n", head, this.b_.toString(16));
		System.err.printf("%s.nG = %S\n", head, this.nG_.toString(16));
		if( null != G_ )
			G_.showInfo(head+".G");
		else
			System.err.printf("%s.G is null\n", head);
		System.err.printf("%s.PC = %d\n", head, this.PC_);
	}
}
