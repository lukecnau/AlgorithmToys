package sm2;

import java.math.BigInteger;

public class ECPoint {
	ECFunction f_;
	public BigInteger x_, y_;
	private int PC_;
	
	private ECPoint() {}
	
	public ECPoint(ECFunction f, BigInteger x, BigInteger y) {
		f_ = f;
		x_ = x;
		y_ = y;
		PC_ = f.PC_;
	}
	
	public BigInteger X() {
		return x_;
	}
	
	public BigInteger Y() {
		return y_;
	}
	
//	@Override
	public ECPoint clone() {
		return new ECPoint(f_, x_, y_);
	}
	
//	//way 1
//	public ECPoint multiply(BigInteger k) {
//		if( null == k )
//			return this;
//		
//		ECPoint q = new ECPoint(f_, 1, BigInteger.ZERO, BigInteger.ZERO);
//
//		for(int i = k.bitLength()-1; i >= 0; --i) {
//			q = q.add(q);
//			
//			if( k.testBit(i) )
//				q = q.add(this);
//
////			q.showInfo("step "+(i));
//		}
//		return q;
//	}
	
	//way 2
	public ECPoint multiply(BigInteger k) {
		if( null == k )
			return this;
		
		ECPoint q = new ECPoint(f_, BigInteger.ZERO, BigInteger.ZERO);
		ECPoint n = this.clone();
		
//		n.showInfo("tmp n");
		
		for(int i = 0; i < k.bitLength(); ++i) {
			if( k.testBit(i) )
				q = q.add(n);
			
			n = n.add(n);
			
//			n.showInfo("Step "+i+","+k.testBit(i)+" n");
//			q.showInfo("Step "+i+","+k.testBit(i)+" q");
		}
		return q;
	}
	
//	//way 3
//	public ECPoint multiply(BigInteger k) {
//		if( null == k )
//			return this;
//		
//		ECPoint q = new ECPoint(f_, 1, BigInteger.ZERO, BigInteger.ZERO);
//		
//		if( 0 == k.compareTo(BigInteger.ZERO) )
//			return q;
//		
//		if( 1 == k.compareTo(BigInteger.ONE))
//			return this;
//		
//		if( 0 == k.mod(BigInteger.TWO).compareTo(BigInteger.ONE))
//			return this.add(this.multiply(k.subtract(BigInteger.ONE)));
//		else
//			return this.add(this).multiply(k.divide(BigInteger.TWO));
//	}
	
	public ECPoint add(ECPoint p2) {
		if( this.isZero() )
			return p2;
		if( null == p2 || p2.isZero() )
			return this;
		if( this.isNegative(p2))
			return Zero();
		
		BigInteger numerator, denominator;
		
		//p1 == p2
//		if( 0 == this.x_.compareTo(p2.x_) && 0 == this.y_.compareTo(p2.y_) ) {
		if( 0 == this.x_.compareTo(p2.x_) ) {
			numerator = this.x_.pow(2).multiply(BigInteger.valueOf(3)).add(f_.a_);
			denominator = this.y_.multiply(BigInteger.TWO);
		} else if(!isEqual(p2)) {
			numerator = p2.y_.subtract(this.y_);
			denominator = p2.x_.subtract(this.x_);
		} else
			return this;
		
		BigInteger t = numerator.mod(f_.p_).multiply(denominator.modInverse(f_.p_));
		
		BigInteger x3 = t.pow(2).subtract(this.x_).subtract(p2.x_).mod(f_.p_);
		BigInteger y3 = t.multiply(this.x_.subtract(x3)).subtract(this.y_).mod(f_.p_);
		
		return new ECPoint(f_, x3, y3);
	}
	
	private boolean isNegative(ECPoint p2) {
		if( null == p2 )
			return false;
		
		if( 0 == this.y_.compareTo(p2.y_.negate()) )
			return true;
		
		return false;
	}

	public boolean isEqual(ECPoint p2) {
		if( (this.f_.equals(p2.f_)) && (0 == this.x_.compareTo(p2.x_)) && (0 == this.y_.compareTo(p2.y_)))
			return true;
		else
			return false;
	}
	
	public boolean isZero() {
		if( 0 == x_.compareTo(BigInteger.ZERO) && 0 == y_.compareTo(BigInteger.ZERO) )
			return true;
		else
			return false;
	}
	
	public ECPoint Zero() {
		return new ECPoint(f_, BigInteger.ZERO, BigInteger.ZERO);
	}
	
	
	public byte[] getKDFBytes() {
//		if( f_.p_.isProbablePrime(0) )
		byte[] xbyte = this.x_.toByteArray();
		byte[] ybyte = this.y_.toByteArray();
		byte[] rbyte = new byte[xbyte.length+ybyte.length];
		
		for(int i = 0; i < xbyte.length; ++i) rbyte[i] = xbyte[i];
		for(int i = 0; i < ybyte.length; ++i) rbyte[xbyte.length+i] = ybyte[i];
		
		return rbyte;
	}
	
	public void showInfo(String head) {
		System.err.printf("%s.x = %S ", head, this.x_.toString(16));
		System.err.printf("%s.y = %S ", head, this.y_.toString(16));
		System.err.printf("%s.PC = %d\n", head, this.PC_);
	}
}
