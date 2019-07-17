package sm3;

//spec: https://tools.ietf.org/html/draft-shen-sm3-hash-01
//online test:https://8gwifi.org/MessageDigest.jsp
//http://www.sca.gov.cn/sca/xwdt/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf

public class testSM3Main {
	private static void testSM3() {
		SM3 sm3 = new SM3();
		
		StringBuffer msg = new StringBuffer("abc"); //result: 66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0
		byte[] to =new byte[sm3.getResultBytesSize()];
		sm3.Digest(msg.toString().getBytes(), to);
		
		msg.setLength(0);
		msg.append("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"); //result: DEBE9FF92275B8A138604889C18E5A4D6FDB70E5387E5765293DCBA39C0C5732
		to =new byte[sm3.getResultBytesSize()];
		sm3.Digest(msg.toString().getBytes(), to);
		
		msg.setLength(0);
		msg.append("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"); //result: 639B6CC5E64D9E37A390B192DF4FA1EA0720AB747FF692B9F38C4E66AD7B8C05
		to =new byte[sm3.getResultBytesSize()];
		sm3.Digest(msg.toString().getBytes(), to);
		
		msg.setLength(0);
		msg.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"); //result: 2971D10C8842B70C979E55063480C50BACFFD90E98E2E60D2512AB8ABFDFCEC5
		to =new byte[sm3.getResultBytesSize()];
		sm3.Digest(msg.toString().getBytes(), to);
		
		msg.setLength(0);
		msg.append("12345678901234567890123456789012345678901234567890123456789012345678901234567890"); //result: AD81805321F3E69D251235BF886A564844873B56DD7DDE400F055B7DDE39307A
		to =new byte[sm3.getResultBytesSize()];
		sm3.Digest(msg.toString().getBytes(), to);
	}

	
	public static void main(String[] args) {
		testSM3();
	}
}
