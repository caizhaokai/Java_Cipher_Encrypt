package com.github.encrypt.encryptTypeImpl;


/**
 * 16进制工具类
 */
public class HexUtil {
	private static final char[] HEX_CHARS = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

	/**
	 * 十六进制转化为二进制
	 */
	public static byte[] hexStrToByteArray(String hexString) {
		if (hexString == null) {
			return null;
		}
		if (hexString.length() == 0) {
			return new byte[0];
		}
		byte[] byteArray = new byte[hexString.length() / 2];
		for (int i = 0; i < byteArray.length; i++) {
			String subStr = hexString.substring(2 * i, 2 * i + 2);
			byteArray[i] = ((byte) Integer.parseInt(subStr, 16));
		}
		return byteArray;
	}

	/**
	 * 二进制转化为十六进制
	 */
	public static String byteArrayToHexStr(byte[] byteArray) {
		if (byteArray == null) {
			return null;
		}
		char[] hexChars = new char[byteArray.length * 2];
		for (int j = 0; j < byteArray.length; j++) {
			int v = byteArray[j] & 0xFF;
			hexChars[j * 2] = HEX_CHARS[v >>> 4];
			hexChars[j * 2 + 1] = HEX_CHARS[v & 0x0F];
		}
		return new String(hexChars);
	}
}
