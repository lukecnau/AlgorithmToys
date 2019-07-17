package tools;

public class LOG {
	private volatile static LOG uniqueInstance;
	public volatile static boolean off = false;
	
	private LOG() {}
	
	public static LOG getInstance() {
		if( null == uniqueInstance ) {
			synchronized (LOG.class) {
				if( null == uniqueInstance )
					uniqueInstance = new LOG();
			}
		}
		return uniqueInstance;
	}
	
	private final byte[] MASK = {(byte) 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01};
	
	//bytes in binary
	public void printBytesInBinary(byte[] value) {
		if( null == value || off ) return ;
			
		for(int i = 0; i < value.length; ++i) {
			for(int j = 7; j >= 0; --j) {
				if( ((byte)((value[i]&0xff) >>> j) & 0x01) == 0x01 )
					System.err.print("1");
				else
					System.err.print("0");
			}
			if( i < value.length-1 )
				System.err.print(" ");
		}
		System.err.println();
	}
	
	public void printBytesInBinary(Byte[] value) {
		if( null == value  || off) return ;
		
		byte[] t = new byte[value.length];
		for( int i = 0; i < t.length; ++i)
			t[i] = value[i];
		
		printBytesInBinary(t);
	}
	
	public void printBytesInBinary(String title, byte[] value) {
		if( null == value  || off ) return ;
		
		System.err.print(title+": ");
		printBytesInBinary(value);
	}
	
	public void printBytesInBinary(String title, Byte[] value) {
		if( null == value  || off ) return ;
		
		System.err.print(title+": ");
		printBytesInBinary(value);
	}
	
	//bytes in binary, printed seperatly by sepbit
	public void printBytesInBinary(int sepbit, byte[] value, int maxbits) {
		if( null == value || off  ) return ;

		for(int i = 0; i < value.length; ++i) {
			for(int j = 0; j < 8; ++j) {
				if( (value[i] & 0xff & MASK[j]) == 0 )
					System.err.print("0");
				else
					System.err.print("1");
			
				if( (i*8+j+1)%(sepbit) == 0  )
					System.err.print(" ");
				
				if( (i*8+j+1) == maxbits ) {
					System.err.println();
					return ;
				}
			}
		}
		
	}
	
	public void printBytesInBinary(String title, byte[] value, int sepbit, int bits) {
		if( null == value || off ) return ;
		
		System.err.print(title+": ");
		printBytesInBinary(sepbit, value,  bits);
	}
	
	//byte in binary
	public void printByteInBinary(byte value) {
		if( off ) return ;
		
		for (int j = 7; j >= 0; --j) {
			if (((byte) ((value&0xff) >>> j) & 0x01) == 0x01)
				System.err.print("1");
			else
				System.err.print("0");
		}
		System.err.println();
	}
	
	public void printByteInBinary(String title, byte value) {
		System.err.print(title+": ");
		printByteInBinary(value);
	}
	
	public String getByteInBinary(byte value) {
		if( off ) return "";
		
		String t = "";
		for (int j = 7; j >= 0; --j) {
			if (((byte) ((value&0xff) >>> j) & (byte)0x01) == (byte)0x01)
				t = t + "1";
			else
				t = t + "0";
		}
		return t;
	}
	
	//bytes in hex
	public void printBytesInHEX(byte[] value) {
		if( null == value  || off ) return ;
		
		System.err.print("0x");
		for(int i = 0; i < value.length; ++i) {
			System.err.printf("%02X", value[i]);
		}
		System.err.println();
	}
	
	public void printBytesInHEX(String title, byte[] value) {
		if( null == value  || off ) return ;
		
		System.err.print(title+": ");
		if( value.length > 0 ) printBytesInHEX(value);
		else System.err.println();
	}
	
	public void printBytesInHEX(String title, byte[] value, int start, int count) {
		if( null == value || value.length < (start+count)  || off ) return ;
		
		System.err.println(title+": "+getBytesInHEX(value, start, count));
	}
	
	public void printBytesInHEX(Byte[] value) {
		if( null == value || off  ) return ;
		
		byte[] t = new byte[value.length];
		for( int i = 0; i < t.length; ++i)
			t[i] = value[i];
		
		printBytesInHEX(t);
	}
	
	public void printBytesInHEX(String title, Byte[] value) {
		if( null == value || off  ) return ;
		
		System.err.print(title+": ");
		printBytesInHEX(value);
	}
	
	public String getBytesInHEX(byte[] value) {
		if( null == value || off  ) return "";
		
		String t = "0x";
		for(int i = 0; i < value.length; ++i) {
			String vstr = String.format("%02x", value[i]);
			t += vstr;
		}
		return t;
	}
	
	public String getBytesInHEX(byte[] value, int start, int count) {
		if( null == value || value.length < (start+count)  || off ) return "";
		
		String t = "0x";
		for(int i = 0; i < count; ++i) {
			String vstr = String.format("%02x", value[i+start]);
			t += vstr;
		}
		return t;
	}
	
	//byte to word in hex
	public String getWordInHEX(byte[] value) {
		if( null == value  || off ) return "";
		
		String t = "0x";
		for(int i = 0; i < 4; ++i) {
			String vstr = String.format("%02x", value[i]);
			t += vstr;
		}
		return t;
	}
	
	public String getWordInHEX(byte[] value, int start) {
		if( null == value || value.length < (start+4)  || off ) return "";
		
		String t = "0x";
		for(int i = 0; i < 4; ++i) {
			String vstr = String.format("%02x", value[i+start]);
			t += vstr;
		}
		return t;
	}
	
	//bytes in dec
	public void printBytesInDEC(byte[] value) {
		if( null == value  || off ) return ;
		
		for(int i = 0; i < value.length; ++i) {
			System.err.printf("%d", value[i]);
		}
		System.err.println();
	}
	
	public void printBytesInDEC(String title, byte[] value) {
		if( null == value  || off ) return ;
		
		System.err.print(title+": ");
		printBytesInDEC(value);
	}

	//word in hex
	public void printIntegersInHEX(int[] value) {
		if( null == value  || off ) return ;
		
		System.err.print("0x");
		for(int i = 0; i < value.length; ++i) {
			System.err.printf("%08X", value[i]);
		}
		System.err.println();
	}
	
	public void printIntegersInHEX(String title, int[] value) {
		if( null == value  || off ) return ;
		
		System.err.print(title+": ");
		printIntegersInHEX(value);
	}
	
	//long in hex
	public void printLongsInHEX(long[] value) {
		if( null == value  || off ) return ;
		
		System.err.print("0x");
		for(int i = 0; i < value.length; ++i) {
			System.err.printf("%016X", value[i]);
		}
		System.err.println();
	}
	
	public void printLongsInHEX(String title, long[] value) {
		if( null == value  || off ) return ;
		
		System.err.print(title+": ");
		printLongsInHEX(value);
	}
}
