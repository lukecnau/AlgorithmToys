package md5;

import tools.TOOLS;

public class testMD5Main {
	private static TOOLS tools = TOOLS.getInstance();
	
	public static void testDigest() {
		MD5 md5 = new MD5();
		
		StringBuffer msg = new StringBuffer();
		byte[] to = new byte[md5.MD5_OUTPUT_BYTES];
		
		msg.setLength(0);
		msg.append(""); //result =: 0xD41D8CD98F00B204E9800998ECF8427E
		msg.toString().getBytes();
		tools.zeroArray(to);
		md5.Digest(msg.toString().getBytes(), to);
		
		msg.setLength(0);
		msg.append("a"); //result =: 0x0CC175B9C0F1B6A831C399E269772661
		msg.toString().getBytes();
		tools.zeroArray(to);
		md5.Digest(msg.toString().getBytes(), to);
		
		msg.setLength(0);
		msg.append("abc"); //result =: 0x900150983CD24FB0D6963F7D28E17F72
		msg.toString().getBytes();
		tools.zeroArray(to);
		md5.Digest(msg.toString().getBytes(), to);
		
		msg.setLength(0);
		msg.append("message digest"); //result =: 0xF96B697D7CB7938D525A2F31AAF161D0
		msg.toString().getBytes();
		tools.zeroArray(to);
		md5.Digest(msg.toString().getBytes(), to);
		
		msg.setLength(0);
		msg.append("abcdefghijklmnopqrstuvwxyz"); //result =: 0xC3FCD3D76192E4007DFB496CCA67E13B
		msg.toString().getBytes();
		tools.zeroArray(to);
		md5.Digest(msg.toString().getBytes(), to);
		
		msg.setLength(0);
		msg.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"); //result =: 0xD174AB98D277D9F5A5611C2C9F419D9F
		msg.toString().getBytes();
		tools.zeroArray(to);
		md5.Digest(msg.toString().getBytes(), to);
		
		msg.setLength(0);
		msg.append("12345678901234567890123456789012345678901234567890123456789012345678901234567890"); //result =: 0x57EDF4A22BE3C955AC49DA2E2107B67A
		msg.toString().getBytes();
		tools.zeroArray(to);
		md5.Digest(msg.toString().getBytes(), to);
	}
	
	public static void testT() {
		MD5 md5 = new MD5();
		
		for(int i = 0; i < 64; ++i)
			System.err.printf("t()=0x%08x\n", md5.T(i+1));
		
	}
	
	public static void main(String[] args) {
//		testT();
		
		testDigest();
	}

}
