package sha;

//https://tools.ietf.org/html/rfc6234
//online test: https://emn178.github.io/online-tools/index.html
//online test: https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values

public class testSHAMain {
	private static void testSHA224() {
		SHA_224 sha = new SHA_224();
		
		StringBuffer msg = new StringBuffer("abc"); //result: 23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7
		byte[] to =new byte[sha.getResultBytesSize()];
		sha.Digest(msg.toString().getBytes(), to);
		
		msg.setLength(0);
		msg.append("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"); //result: 75388B16512776CC5DBA5DA1FD890150B0C6455CB4F58B1952522525
		to =new byte[sha.getResultBytesSize()];
		sha.Digest(msg.toString().getBytes(), to);
		
		msg.setLength(0);
		msg.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"); //result: BFF72B4FCB7D75E5632900AC5F90D219E05E97A7BDE72E740DB393D9
		to =new byte[sha.getResultBytesSize()];
		sha.Digest(msg.toString().getBytes(), to);
		
		msg.setLength(0);
		msg.append("12345678901234567890123456789012345678901234567890123456789012345678901234567890"); //result: B50AECBE4E9BB0B57BC5F3AE760A8E01DB24F203FB3CDCD13148046E
		to =new byte[sha.getResultBytesSize()];
		sha.Digest(msg.toString().getBytes(), to);
	}
	
	private static void testSHA256() {
		SHA_256 sha = new SHA_256();
		
		StringBuffer msg = new StringBuffer("abc"); //result: BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD
		byte[] to =new byte[sha.getResultBytesSize()];
		sha.Digest(msg.toString().getBytes(), to);
		
		msg.setLength(0);
		msg.append("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"); //result: 248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1
		to =new byte[sha.getResultBytesSize()];
		sha.Digest(msg.toString().getBytes(), to);
		
		msg.setLength(0);
		msg.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"); //result: DB4BFCBD4DA0CD85A60C3C37D3FBD8805C77F15FC6B1FDFE614EE0A7C8FDB4C0
		to =new byte[sha.getResultBytesSize()];
		sha.Digest(msg.toString().getBytes(), to);
		
		msg.setLength(0);
		msg.append("12345678901234567890123456789012345678901234567890123456789012345678901234567890"); //result: F371BC4A311F2B009EEF952DD83CA80E2B60026C8E935592D0F9C308453C813E
		to =new byte[sha.getResultBytesSize()];
		sha.Digest(msg.toString().getBytes(), to);
	}
	
	private static void testSHA512() {
		SHA_512 sha = new SHA_512();
		
		StringBuffer msg = new StringBuffer("abc"); //result: DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F
		byte[] to =new byte[sha.getResultBytesSize()];
		sha.Digest(msg.toString().getBytes(), to);
		
		msg.setLength(0);
		msg.append("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"); //result: 8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909
		to =new byte[sha.getResultBytesSize()];
		sha.Digest(msg.toString().getBytes(), to);
		
		msg.setLength(0);
		msg.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"); //result: 91BF61016AF96FE4EC4CA50C66CEFF37CEAE016F355449BBF16D6223A030332F56E0CA1E170572930CEE69D9D6BC32C5B4E5E1911B7A910386D8730155B8A96F
		to =new byte[sha.getResultBytesSize()];
		sha.Digest(msg.toString().getBytes(), to);
		
		msg.setLength(0);
		msg.append("1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"); //result: 72BF79456740D55C96AD9301A353D6F821910AE3B2E9B2F40220630D4FC61C2C2D8CE3FA42A2FB744B39D59F08BA5F3678972B20A1C7AE5061D4919F1B1B0234
		to =new byte[sha.getResultBytesSize()];
		sha.Digest(msg.toString().getBytes(), to);
	}
	
	private static void testRotation() {
		int a = 0x80000000;
		
		for(int i = 0; i < 32; ++i)
			System.err.printf("rotateleft %d: %08X\n", i, Integer.rotateLeft(a, i));
		
		System.err.println();
		
		for(int i = 0; i < 32; ++i)
			System.err.printf("rotateright %d: %08X\n", i, Integer.rotateRight(a, i));
	}
	
	public static void main(String[] args) {
		testSHA224();
		
		testSHA256();
		
		testSHA512();
		
//		testRotation();
	}

}
