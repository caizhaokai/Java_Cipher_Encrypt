package com.github.encrypt;

import com.github.encrypt.EncryptEnum.AseEnum;
import com.github.encrypt.EncryptEnum.Dec3Enum;
import com.github.encrypt.EncryptEnum.DecEnum;
import com.github.encrypt.EncryptEnum.MDEnum;
import com.github.encrypt.EncryptEnum.RSAEnum;
import com.github.encrypt.EncryptEnum.ShaEnum;

/**
 * 测试
 */
public class EncryptTest {
	public static void main(String[] args) throws Exception {
//		mdTest();
//		shaTest();
//		desBaseTest();
//		desHexTest();
//		des3BaseTest();
//		desHexTest();
//		aesBaseTest();
//		aesHexTest();
//		aesKGngBaseTest();
//		aesKGngHexTest();
//		rsaBaseTest();
		rsaHexTest();
	}
	
	public static void mdTest() {
		System.out.println(EncryptUtil.MD_ENCRYPT.encryptBase64("123456"));
		System.out.println(EncryptUtil.MD_ENCRYPT.encryptBase64("123456", MDEnum.MD2));
		System.out.println(EncryptUtil.MD_ENCRYPT.encryptBase64("123456", MDEnum.MD5));
		System.out.println(EncryptUtil.MD_ENCRYPT.encryptBase64("123456", "password"));
		System.out.println(EncryptUtil.MD_ENCRYPT.encryptBase64("123456", "password", MDEnum.MD5));
		
		System.out.println(EncryptUtil.MD_ENCRYPT.encryptHex("123456"));
		System.out.println(EncryptUtil.MD_ENCRYPT.encryptHex("123456", MDEnum.MD2));
		System.out.println(EncryptUtil.MD_ENCRYPT.encryptHex("123456", MDEnum.MD5));
		System.out.println(EncryptUtil.MD_ENCRYPT.encryptHex("123456", "password"));
		System.out.println(EncryptUtil.MD_ENCRYPT.encryptHex("123456", "password", MDEnum.MD5));
	}
	
	public static void shaTest() {
		System.out.println(EncryptUtil.SHA_ENCRYPT.encryptBase64("123456"));
		System.out.println(EncryptUtil.SHA_ENCRYPT.encryptBase64("123456", ShaEnum.SHA1));
		System.out.println(EncryptUtil.SHA_ENCRYPT.encryptBase64("123456", ShaEnum.SHA224));
		System.out.println(EncryptUtil.SHA_ENCRYPT.encryptBase64("123456", ShaEnum.SHA256));
		System.out.println(EncryptUtil.SHA_ENCRYPT.encryptBase64("123456", ShaEnum.SHA384));
		System.out.println(EncryptUtil.SHA_ENCRYPT.encryptBase64("123456", ShaEnum.SHA512));
		System.out.println(EncryptUtil.SHA_ENCRYPT.encryptBase64("123456", "password"));
		System.out.println(EncryptUtil.SHA_ENCRYPT.encryptBase64("123456", "password", ShaEnum.SHA256));
		
		System.out.println(EncryptUtil.SHA_ENCRYPT.encryptHex("123456"));
		System.out.println(EncryptUtil.SHA_ENCRYPT.encryptHex("123456", ShaEnum.SHA1));
		System.out.println(EncryptUtil.SHA_ENCRYPT.encryptHex("123456", ShaEnum.SHA224));
		System.out.println(EncryptUtil.SHA_ENCRYPT.encryptHex("123456", ShaEnum.SHA256));
		System.out.println(EncryptUtil.SHA_ENCRYPT.encryptHex("123456", ShaEnum.SHA384));
		System.out.println(EncryptUtil.SHA_ENCRYPT.encryptHex("123456", ShaEnum.SHA512));
		System.out.println(EncryptUtil.SHA_ENCRYPT.encryptHex("123456", "password"));
		System.out.println(EncryptUtil.SHA_ENCRYPT.encryptHex("123456", "password", ShaEnum.SHA256));
	}
	
	public static void desBaseTest() throws Exception {
		String s1 = EncryptUtil.DES_ENCRYPT.encryptBase64("123456");
		System.out.println(s1);
		System.out.println(EncryptUtil.DES_ENCRYPT.decryptBase64(s1));
		
		String s2 = EncryptUtil.DES_ENCRYPT.encryptBase64("123456", "password", "passw0rd");
		System.out.println(s2);
		System.out.println(EncryptUtil.DES_ENCRYPT.decryptBase64(s2, "password", "passw0rd"));
		
		String s3 = EncryptUtil.DES_ENCRYPT.encryptBase64("123456", DecEnum.CBC_NO_PADDING);
		String s4 = EncryptUtil.DES_ENCRYPT.encryptBase64("123456", DecEnum.CBC_PKCS5PADDING);
		String s5 = EncryptUtil.DES_ENCRYPT.encryptBase64("123456", DecEnum.ECB_NO_PADDING);
		String s6 = EncryptUtil.DES_ENCRYPT.encryptBase64("123456", DecEnum.ECB_PKCS5PADDING);
		System.out.println(s3);
		System.out.println(s4);
		System.out.println(s5);
		System.out.println(s6);
		System.out.println(EncryptUtil.DES_ENCRYPT.decryptBase64(s3, DecEnum.CBC_NO_PADDING));
		System.out.println(EncryptUtil.DES_ENCRYPT.decryptBase64(s4, DecEnum.CBC_PKCS5PADDING));
		System.out.println(EncryptUtil.DES_ENCRYPT.decryptBase64(s5, DecEnum.ECB_NO_PADDING));
		System.out.println(EncryptUtil.DES_ENCRYPT.decryptBase64(s6, DecEnum.ECB_PKCS5PADDING));
		
		String s7 = EncryptUtil.DES_ENCRYPT.encryptBase64("123456", "password", "passw0rd", DecEnum.CBC_NO_PADDING);
		String s8 = EncryptUtil.DES_ENCRYPT.encryptBase64("123456", "password", "passw0rd", DecEnum.CBC_PKCS5PADDING);
		String s9 = EncryptUtil.DES_ENCRYPT.encryptBase64("123456", "password", null, DecEnum.ECB_NO_PADDING);
		String s10 = EncryptUtil.DES_ENCRYPT.encryptBase64("123456", "password", null, DecEnum.ECB_PKCS5PADDING);
		System.out.println(s7);
		System.out.println(s8);
		System.out.println(s9);
		System.out.println(s10);
		System.out.println(EncryptUtil.DES_ENCRYPT.decryptBase64(s7, "password", "passw0rd", DecEnum.CBC_NO_PADDING));
		System.out.println(EncryptUtil.DES_ENCRYPT.decryptBase64(s8, "password", "passw0rd", DecEnum.CBC_PKCS5PADDING));
		System.out.println(EncryptUtil.DES_ENCRYPT.decryptBase64(s9, "password", null, DecEnum.ECB_NO_PADDING));
		System.out.println(EncryptUtil.DES_ENCRYPT.decryptBase64(s10, "password", null, DecEnum.ECB_PKCS5PADDING));
	}
	
	public static void desHexTest() throws Exception {
		String s1 = EncryptUtil.DES_ENCRYPT.encryptHex("123456");
		System.out.println(s1);
		System.out.println(EncryptUtil.DES_ENCRYPT.decryptHex(s1));
		
		String s2 = EncryptUtil.DES_ENCRYPT.encryptHex("123456", "password", "passw0rd");
		System.out.println(s2);
		System.out.println(EncryptUtil.DES_ENCRYPT.decryptHex(s2, "password", "passw0rd"));
		
		String s3 = EncryptUtil.DES_ENCRYPT.encryptHex("123456", DecEnum.CBC_NO_PADDING);
		String s4 = EncryptUtil.DES_ENCRYPT.encryptHex("123456", DecEnum.CBC_PKCS5PADDING);
		String s5 = EncryptUtil.DES_ENCRYPT.encryptHex("123456", DecEnum.ECB_NO_PADDING);
		String s6 = EncryptUtil.DES_ENCRYPT.encryptHex("123456", DecEnum.ECB_PKCS5PADDING);
		System.out.println(s3);
		System.out.println(s4);
		System.out.println(s5);
		System.out.println(s6);
		System.out.println(EncryptUtil.DES_ENCRYPT.decryptHex(s3, DecEnum.CBC_NO_PADDING));
		System.out.println(EncryptUtil.DES_ENCRYPT.decryptHex(s4, DecEnum.CBC_PKCS5PADDING));
		System.out.println(EncryptUtil.DES_ENCRYPT.decryptHex(s5, DecEnum.ECB_NO_PADDING));
		System.out.println(EncryptUtil.DES_ENCRYPT.decryptHex(s6, DecEnum.ECB_PKCS5PADDING));
		
		String s7 = EncryptUtil.DES_ENCRYPT.encryptHex("123456", "password", "passw0rd", DecEnum.CBC_NO_PADDING);
		String s8 = EncryptUtil.DES_ENCRYPT.encryptHex("123456", "password", "passw0rd", DecEnum.CBC_PKCS5PADDING);
		String s9 = EncryptUtil.DES_ENCRYPT.encryptHex("123456", "password", null, DecEnum.ECB_NO_PADDING);
		String s10 = EncryptUtil.DES_ENCRYPT.encryptHex("123456", "password", null, DecEnum.ECB_PKCS5PADDING);
		System.out.println(s7);
		System.out.println(s8);
		System.out.println(s9);
		System.out.println(s10);
		System.out.println(EncryptUtil.DES_ENCRYPT.decryptHex(s7, "password", "passw0rd", DecEnum.CBC_NO_PADDING));
		System.out.println(EncryptUtil.DES_ENCRYPT.decryptHex(s8, "password", "passw0rd", DecEnum.CBC_PKCS5PADDING));
		System.out.println(EncryptUtil.DES_ENCRYPT.decryptHex(s9, "password", null, DecEnum.ECB_NO_PADDING));
		System.out.println(EncryptUtil.DES_ENCRYPT.decryptHex(s10, "password", null, DecEnum.ECB_PKCS5PADDING));
	}
	
	public static void des3BaseTest() throws Exception {
		String s1 = EncryptUtil.DES3_ENCRYPT.encryptBase64("123456");
		System.out.println(s1);
		System.out.println(EncryptUtil.DES3_ENCRYPT.decryptBase64(s1));
		
		String s2 = EncryptUtil.DES3_ENCRYPT.encryptBase64("123456", "passwordpasswordpassword", "passw0rd");
		System.out.println(s2);
		System.out.println(EncryptUtil.DES3_ENCRYPT.decryptBase64(s2, "passwordpasswordpassword", "passw0rd"));
		
		String s3 = EncryptUtil.DES3_ENCRYPT.encryptBase64("123456", Dec3Enum.CBC_NO_PADDING);
		String s4 = EncryptUtil.DES3_ENCRYPT.encryptBase64("123456", Dec3Enum.CBC_PKCS5PADDING);
		String s5 = EncryptUtil.DES3_ENCRYPT.encryptBase64("123456", Dec3Enum.ECB_NO_PADDING);
		String s6 = EncryptUtil.DES3_ENCRYPT.encryptBase64("123456", Dec3Enum.ECB_PKCS5PADDING);
		System.out.println(s3);
		System.out.println(s4);
		System.out.println(s5);
		System.out.println(s6);
		System.out.println(EncryptUtil.DES3_ENCRYPT.decryptBase64(s3, Dec3Enum.CBC_NO_PADDING));
		System.out.println(EncryptUtil.DES3_ENCRYPT.decryptBase64(s4, Dec3Enum.CBC_PKCS5PADDING));
		System.out.println(EncryptUtil.DES3_ENCRYPT.decryptBase64(s5, Dec3Enum.ECB_NO_PADDING));
		System.out.println(EncryptUtil.DES3_ENCRYPT.decryptBase64(s6, Dec3Enum.ECB_PKCS5PADDING));
		
		String s7 = EncryptUtil.DES3_ENCRYPT.encryptBase64("123456", "passwordpasswordpassword", "passw0rd", Dec3Enum.CBC_NO_PADDING);
		String s8 = EncryptUtil.DES3_ENCRYPT.encryptBase64("123456", "passwordpasswordpassword", "passw0rd", Dec3Enum.CBC_PKCS5PADDING);
		String s9 = EncryptUtil.DES3_ENCRYPT.encryptBase64("123456", "passwordpasswordpassword", null, Dec3Enum.ECB_NO_PADDING);
		String s10 = EncryptUtil.DES3_ENCRYPT.encryptBase64("123456", "passwordpasswordpassword", null, Dec3Enum.ECB_PKCS5PADDING);
		System.out.println(s7);
		System.out.println(s8);
		System.out.println(s9);
		System.out.println(s10);
		System.out.println(EncryptUtil.DES3_ENCRYPT.decryptBase64(s7, "passwordpasswordpassword", "passw0rd", Dec3Enum.CBC_NO_PADDING));
		System.out.println(EncryptUtil.DES3_ENCRYPT.decryptBase64(s8, "passwordpasswordpassword", "passw0rd", Dec3Enum.CBC_PKCS5PADDING));
		System.out.println(EncryptUtil.DES3_ENCRYPT.decryptBase64(s9, "passwordpasswordpassword", null, Dec3Enum.ECB_NO_PADDING));
		System.out.println(EncryptUtil.DES3_ENCRYPT.decryptBase64(s10, "passwordpasswordpassword", null, Dec3Enum.ECB_PKCS5PADDING));
	}
	
	public static void des3HexTest() throws Exception {
		String s1 = EncryptUtil.DES3_ENCRYPT.encryptHex("123456");
		System.out.println(s1);
		System.out.println(EncryptUtil.DES3_ENCRYPT.decryptHex(s1));
		
		String s2 = EncryptUtil.DES3_ENCRYPT.encryptHex("123456", "passwordpasswordpassword", "passw0rd");
		System.out.println(s2);
		System.out.println(EncryptUtil.DES3_ENCRYPT.decryptHex(s2, "passwordpasswordpassword", "passw0rd"));
		
		String s3 = EncryptUtil.DES3_ENCRYPT.encryptHex("123456", Dec3Enum.CBC_NO_PADDING);
		String s4 = EncryptUtil.DES3_ENCRYPT.encryptHex("123456", Dec3Enum.CBC_PKCS5PADDING);
		String s5 = EncryptUtil.DES3_ENCRYPT.encryptHex("123456", Dec3Enum.ECB_NO_PADDING);
		String s6 = EncryptUtil.DES3_ENCRYPT.encryptHex("123456", Dec3Enum.ECB_PKCS5PADDING);
		System.out.println(s3);
		System.out.println(s4);
		System.out.println(s5);
		System.out.println(s6);
		System.out.println(EncryptUtil.DES3_ENCRYPT.decryptHex(s3, Dec3Enum.CBC_NO_PADDING));
		System.out.println(EncryptUtil.DES3_ENCRYPT.decryptHex(s4, Dec3Enum.CBC_PKCS5PADDING));
		System.out.println(EncryptUtil.DES3_ENCRYPT.decryptHex(s5, Dec3Enum.ECB_NO_PADDING));
		System.out.println(EncryptUtil.DES3_ENCRYPT.decryptHex(s6, Dec3Enum.ECB_PKCS5PADDING));
		
		String s7 = EncryptUtil.DES3_ENCRYPT.encryptHex("123456", "passwordpasswordpassword", "passw0rd", Dec3Enum.CBC_NO_PADDING);
		String s8 = EncryptUtil.DES3_ENCRYPT.encryptHex("123456", "passwordpasswordpassword", "passw0rd", Dec3Enum.CBC_PKCS5PADDING);
		String s9 = EncryptUtil.DES3_ENCRYPT.encryptHex("123456", "passwordpasswordpassword", null, Dec3Enum.ECB_NO_PADDING);
		String s10 = EncryptUtil.DES3_ENCRYPT.encryptHex("123456", "passwordpasswordpassword", null, Dec3Enum.ECB_PKCS5PADDING);
		System.out.println(s7);
		System.out.println(s8);
		System.out.println(s9);
		System.out.println(s10);
		System.out.println(EncryptUtil.DES3_ENCRYPT.decryptHex(s7, "passwordpasswordpassword", "passw0rd", Dec3Enum.CBC_NO_PADDING));
		System.out.println(EncryptUtil.DES3_ENCRYPT.decryptHex(s8, "passwordpasswordpassword", "passw0rd", Dec3Enum.CBC_PKCS5PADDING));
		System.out.println(EncryptUtil.DES3_ENCRYPT.decryptHex(s9, "passwordpasswordpassword", null, Dec3Enum.ECB_NO_PADDING));
		System.out.println(EncryptUtil.DES3_ENCRYPT.decryptHex(s10, "passwordpasswordpassword", null, Dec3Enum.ECB_PKCS5PADDING));
	}
	
	public static void aesBaseTest() throws Exception {
		String s1 = EncryptUtil.AES_ENCRYPT.encryptBase64("123456");
		System.out.println(s1);
		System.out.println(EncryptUtil.AES_ENCRYPT.decryptBase64(s1));
		
		String s2 = EncryptUtil.AES_ENCRYPT.encryptBase64("123456", "passwordpassword", "passw0rdpassw0rd");
		System.out.println(s2);
		System.out.println(EncryptUtil.AES_ENCRYPT.decryptBase64(s2, "passwordpassword", "passw0rdpassw0rd"));
		
		String s3 = EncryptUtil.AES_ENCRYPT.encryptBase64("123456", AseEnum.CBC_NO_PADDING);
		String s4 = EncryptUtil.AES_ENCRYPT.encryptBase64("123456", AseEnum.CBC_PKCS5PADDING);
		String s5 = EncryptUtil.AES_ENCRYPT.encryptBase64("123456", AseEnum.ECB_NO_PADDING);
		String s6 = EncryptUtil.AES_ENCRYPT.encryptBase64("123456", AseEnum.ECB_PKCS5PADDING);
		System.out.println(s3);
		System.out.println(s4);
		System.out.println(s5);
		System.out.println(s6);
		System.out.println(EncryptUtil.AES_ENCRYPT.decryptBase64(s3, AseEnum.CBC_NO_PADDING));
		System.out.println(EncryptUtil.AES_ENCRYPT.decryptBase64(s4, AseEnum.CBC_PKCS5PADDING));
		System.out.println(EncryptUtil.AES_ENCRYPT.decryptBase64(s5, AseEnum.ECB_NO_PADDING));
		System.out.println(EncryptUtil.AES_ENCRYPT.decryptBase64(s6, AseEnum.ECB_PKCS5PADDING));
		
		String s7 = EncryptUtil.AES_ENCRYPT.encryptBase64("123456", "passwordpassword", "passw0rdpassw0rd", AseEnum.CBC_NO_PADDING);
		String s8 = EncryptUtil.AES_ENCRYPT.encryptBase64("123456", "passwordpassword", "passw0rdpassw0rd", AseEnum.CBC_PKCS5PADDING);
		String s9 = EncryptUtil.AES_ENCRYPT.encryptBase64("123456", "passwordpassword", null, AseEnum.ECB_NO_PADDING);
		String s10 = EncryptUtil.AES_ENCRYPT.encryptBase64("123456", "passwordpassword", null, AseEnum.ECB_PKCS5PADDING);
		System.out.println(s7);
		System.out.println(s8);
		System.out.println(s9);
		System.out.println(s10);
		System.out.println(EncryptUtil.AES_ENCRYPT.decryptBase64(s7, "passwordpassword", "passw0rdpassw0rd", AseEnum.CBC_NO_PADDING));
		System.out.println(EncryptUtil.AES_ENCRYPT.decryptBase64(s8, "passwordpassword", "passw0rdpassw0rd", AseEnum.CBC_PKCS5PADDING));
		System.out.println(EncryptUtil.AES_ENCRYPT.decryptBase64(s9, "passwordpassword", null, AseEnum.ECB_NO_PADDING));
		System.out.println(EncryptUtil.AES_ENCRYPT.decryptBase64(s10, "passwordpassword", null, AseEnum.ECB_PKCS5PADDING));
	}
	
	public static void aesHexTest() throws Exception {
		String s1 = EncryptUtil.AES_ENCRYPT.encryptHex("123456");
		System.out.println(s1);
		System.out.println(EncryptUtil.AES_ENCRYPT.decryptHex(s1));
		
		String s2 = EncryptUtil.AES_ENCRYPT.encryptHex("123456", "passwordpassword", "passw0rdpassw0rd");
		System.out.println(s2);
		System.out.println(EncryptUtil.AES_ENCRYPT.decryptHex(s2, "passwordpassword", "passw0rdpassw0rd"));
		
		String s3 = EncryptUtil.AES_ENCRYPT.encryptHex("123456", AseEnum.CBC_NO_PADDING);
		String s4 = EncryptUtil.AES_ENCRYPT.encryptHex("123456", AseEnum.CBC_PKCS5PADDING);
		String s5 = EncryptUtil.AES_ENCRYPT.encryptHex("123456", AseEnum.ECB_NO_PADDING);
		String s6 = EncryptUtil.AES_ENCRYPT.encryptHex("123456", AseEnum.ECB_PKCS5PADDING);
		System.out.println(s3);
		System.out.println(s4);
		System.out.println(s5);
		System.out.println(s6);
		System.out.println(EncryptUtil.AES_ENCRYPT.decryptHex(s3, AseEnum.CBC_NO_PADDING));
		System.out.println(EncryptUtil.AES_ENCRYPT.decryptHex(s4, AseEnum.CBC_PKCS5PADDING));
		System.out.println(EncryptUtil.AES_ENCRYPT.decryptHex(s5, AseEnum.ECB_NO_PADDING));
		System.out.println(EncryptUtil.AES_ENCRYPT.decryptHex(s6, AseEnum.ECB_PKCS5PADDING));
		
		String s7 = EncryptUtil.AES_ENCRYPT.encryptHex("123456", "passwordpassword", "passw0rdpassw0rd", AseEnum.CBC_NO_PADDING);
		String s8 = EncryptUtil.AES_ENCRYPT.encryptHex("123456", "passwordpassword", "passw0rdpassw0rd", AseEnum.CBC_PKCS5PADDING);
		String s9 = EncryptUtil.AES_ENCRYPT.encryptHex("123456", "passwordpassword", null, AseEnum.ECB_NO_PADDING);
		String s10 = EncryptUtil.AES_ENCRYPT.encryptHex("123456", "passwordpassword", null, AseEnum.ECB_PKCS5PADDING);
		System.out.println(s7);
		System.out.println(s8);
		System.out.println(s9);
		System.out.println(s10);
		System.out.println(EncryptUtil.AES_ENCRYPT.decryptHex(s7, "passwordpassword", "passw0rdpassw0rd", AseEnum.CBC_NO_PADDING));
		System.out.println(EncryptUtil.AES_ENCRYPT.decryptHex(s8, "passwordpassword", "passw0rdpassw0rd", AseEnum.CBC_PKCS5PADDING));
		System.out.println(EncryptUtil.AES_ENCRYPT.decryptHex(s9, "passwordpassword", null, AseEnum.ECB_NO_PADDING));
		System.out.println(EncryptUtil.AES_ENCRYPT.decryptHex(s10, "passwordpassword", null, AseEnum.ECB_PKCS5PADDING));
	}
	
	public static void aesKGngBaseTest() throws Exception {
		String s1 = EncryptUtil.AES_KGEN_ENCRYPT.encryptBase64("123456");
		System.out.println(s1);
		System.out.println(EncryptUtil.AES_KGEN_ENCRYPT.decryptBase64(s1));
		
		String s2 = EncryptUtil.AES_KGEN_ENCRYPT.encryptBase64("123456", "password", "passw0rd");
		System.out.println(s2);
		System.out.println(EncryptUtil.AES_KGEN_ENCRYPT.decryptBase64(s2, "password", "passw0rd"));
		
		String s3 = EncryptUtil.AES_KGEN_ENCRYPT.encryptBase64("123456", AseEnum.CBC_NO_PADDING);
		String s4 = EncryptUtil.AES_KGEN_ENCRYPT.encryptBase64("123456", AseEnum.CBC_PKCS5PADDING);
		String s5 = EncryptUtil.AES_KGEN_ENCRYPT.encryptBase64("123456", AseEnum.ECB_NO_PADDING);
		String s6 = EncryptUtil.AES_KGEN_ENCRYPT.encryptBase64("123456", AseEnum.ECB_PKCS5PADDING);
		System.out.println(s3);
		System.out.println(s4);
		System.out.println(s5);
		System.out.println(s6);
		System.out.println(EncryptUtil.AES_KGEN_ENCRYPT.decryptBase64(s3, AseEnum.CBC_NO_PADDING));
		System.out.println(EncryptUtil.AES_KGEN_ENCRYPT.decryptBase64(s4, AseEnum.CBC_PKCS5PADDING));
		System.out.println(EncryptUtil.AES_KGEN_ENCRYPT.decryptBase64(s5, AseEnum.ECB_NO_PADDING));
		System.out.println(EncryptUtil.AES_KGEN_ENCRYPT.decryptBase64(s6, AseEnum.ECB_PKCS5PADDING));
		
		String s7 = EncryptUtil.AES_KGEN_ENCRYPT.encryptBase64("123456", "password", "passw0rd", AseEnum.CBC_NO_PADDING);
		String s8 = EncryptUtil.AES_KGEN_ENCRYPT.encryptBase64("123456", "password", "passw0rd", AseEnum.CBC_PKCS5PADDING);
		String s9 = EncryptUtil.AES_KGEN_ENCRYPT.encryptBase64("123456", "password", null, AseEnum.ECB_NO_PADDING);
		String s10 = EncryptUtil.AES_KGEN_ENCRYPT.encryptBase64("123456", "password", null, AseEnum.ECB_PKCS5PADDING);
		System.out.println(s7);
		System.out.println(s8);
		System.out.println(s9);
		System.out.println(s10);
		System.out.println(EncryptUtil.AES_KGEN_ENCRYPT.decryptBase64(s7, "password", "passw0rd", AseEnum.CBC_NO_PADDING));
		System.out.println(EncryptUtil.AES_KGEN_ENCRYPT.decryptBase64(s8, "password", "passw0rd", AseEnum.CBC_PKCS5PADDING));
		System.out.println(EncryptUtil.AES_KGEN_ENCRYPT.decryptBase64(s9, "password", null, AseEnum.ECB_NO_PADDING));
		System.out.println(EncryptUtil.AES_KGEN_ENCRYPT.decryptBase64(s10, "password", null, AseEnum.ECB_PKCS5PADDING));
	}
	
	public static void aesKGngHexTest() throws Exception {
		String s1 = EncryptUtil.AES_KGEN_ENCRYPT.encryptHex("123456");
		System.out.println(s1);
		System.out.println(EncryptUtil.AES_KGEN_ENCRYPT.decryptHex(s1));
		
		String s2 = EncryptUtil.AES_KGEN_ENCRYPT.encryptHex("123456", "password", "passw0rd");
		System.out.println(s2);
		System.out.println(EncryptUtil.AES_KGEN_ENCRYPT.decryptHex(s2, "password", "passw0rd"));
		
		String s3 = EncryptUtil.AES_KGEN_ENCRYPT.encryptHex("123456", AseEnum.CBC_NO_PADDING);
		String s4 = EncryptUtil.AES_KGEN_ENCRYPT.encryptHex("123456", AseEnum.CBC_PKCS5PADDING);
		String s5 = EncryptUtil.AES_KGEN_ENCRYPT.encryptHex("123456", AseEnum.ECB_NO_PADDING);
		String s6 = EncryptUtil.AES_KGEN_ENCRYPT.encryptHex("123456", AseEnum.ECB_PKCS5PADDING);
		System.out.println(s3);
		System.out.println(s4);
		System.out.println(s5);
		System.out.println(s6);
		System.out.println(EncryptUtil.AES_KGEN_ENCRYPT.decryptHex(s3, AseEnum.CBC_NO_PADDING));
		System.out.println(EncryptUtil.AES_KGEN_ENCRYPT.decryptHex(s4, AseEnum.CBC_PKCS5PADDING));
		System.out.println(EncryptUtil.AES_KGEN_ENCRYPT.decryptHex(s5, AseEnum.ECB_NO_PADDING));
		System.out.println(EncryptUtil.AES_KGEN_ENCRYPT.decryptHex(s6, AseEnum.ECB_PKCS5PADDING));
		
		String s7 = EncryptUtil.AES_KGEN_ENCRYPT.encryptHex("123456", "password", "passw0rd", AseEnum.CBC_NO_PADDING);
		String s8 = EncryptUtil.AES_KGEN_ENCRYPT.encryptHex("123456", "password", "passw0rd", AseEnum.CBC_PKCS5PADDING);
		String s9 = EncryptUtil.AES_KGEN_ENCRYPT.encryptHex("123456", "password", null, AseEnum.ECB_NO_PADDING);
		String s10 = EncryptUtil.AES_KGEN_ENCRYPT.encryptHex("123456", "password", null, AseEnum.ECB_PKCS5PADDING);
		System.out.println(s7);
		System.out.println(s8);
		System.out.println(s9);
		System.out.println(s10);
		System.out.println(EncryptUtil.AES_KGEN_ENCRYPT.decryptHex(s7, "password", "passw0rd", AseEnum.CBC_NO_PADDING));
		System.out.println(EncryptUtil.AES_KGEN_ENCRYPT.decryptHex(s8, "password", "passw0rd", AseEnum.CBC_PKCS5PADDING));
		System.out.println(EncryptUtil.AES_KGEN_ENCRYPT.decryptHex(s9, "password", null, AseEnum.ECB_NO_PADDING));
		System.out.println(EncryptUtil.AES_KGEN_ENCRYPT.decryptHex(s10, "password", null, AseEnum.ECB_PKCS5PADDING));
	}

	public static void rsaBaseTest() throws Exception {
		String s1 = EncryptUtil.RSA_ENCRYPT.encryptBase64("123456");
		System.out.println(s1);
		System.out.println(EncryptUtil.RSA_ENCRYPT.decryptBase64(s1));
		
		String s2 = EncryptUtil.RSA_ENCRYPT.encryptBase64("123456", "password", "passw0rd");
		System.out.println(s2);
		System.out.println(EncryptUtil.RSA_ENCRYPT.decryptBase64(s2, "password", "passw0rd"));
		
		String s3 = EncryptUtil.RSA_ENCRYPT.encryptBase64("123456", RSAEnum.ECB_OAEP_WITH_SHA1_AND_MGF_1PADDING);
		String s4 = EncryptUtil.RSA_ENCRYPT.encryptBase64("123456", RSAEnum.ECB_OAEP_WITH_SHA256_AND_MGF_1PADDING);
		String s5 = EncryptUtil.RSA_ENCRYPT.encryptBase64("123456", RSAEnum.ECB_PKCS1PADDING);
		System.out.println(s3);
		System.out.println(s4);
		System.out.println(s5);
		System.out.println(EncryptUtil.RSA_ENCRYPT.decryptBase64(s3, RSAEnum.ECB_OAEP_WITH_SHA1_AND_MGF_1PADDING));
		System.out.println(EncryptUtil.RSA_ENCRYPT.decryptBase64(s4, RSAEnum.ECB_OAEP_WITH_SHA256_AND_MGF_1PADDING));
		System.out.println(EncryptUtil.RSA_ENCRYPT.decryptBase64(s5, RSAEnum.ECB_PKCS1PADDING));
		
		String s6 = EncryptUtil.RSA_ENCRYPT.encryptBase64("123456", "password", null, RSAEnum.ECB_OAEP_WITH_SHA1_AND_MGF_1PADDING);
		String s7 = EncryptUtil.RSA_ENCRYPT.encryptBase64("123456", "password", null, RSAEnum.ECB_OAEP_WITH_SHA256_AND_MGF_1PADDING);
		String s8 = EncryptUtil.RSA_ENCRYPT.encryptBase64("123456", "password", null, RSAEnum.ECB_PKCS1PADDING);
		System.out.println(s6);
		System.out.println(s7);
		System.out.println(s8);
		System.out.println(EncryptUtil.RSA_ENCRYPT.decryptBase64(s6, "password", null, RSAEnum.ECB_OAEP_WITH_SHA1_AND_MGF_1PADDING));
		System.out.println(EncryptUtil.RSA_ENCRYPT.decryptBase64(s7, "password", null, RSAEnum.ECB_OAEP_WITH_SHA256_AND_MGF_1PADDING));
		System.out.println(EncryptUtil.RSA_ENCRYPT.decryptBase64(s8, "password", null, RSAEnum.ECB_PKCS1PADDING));
	}
	
	public static void rsaHexTest() throws Exception {
		String s1 = EncryptUtil.RSA_ENCRYPT.encryptHex("123456");
		System.out.println(s1);
		System.out.println(EncryptUtil.RSA_ENCRYPT.decryptHex(s1));
		
		String s2 = EncryptUtil.RSA_ENCRYPT.encryptHex("123456", "password", "passw0rd");
		System.out.println(s2);
		System.out.println(EncryptUtil.RSA_ENCRYPT.decryptHex(s2, "password", "passw0rd"));
		
		String s3 = EncryptUtil.RSA_ENCRYPT.encryptHex("123456", RSAEnum.ECB_OAEP_WITH_SHA1_AND_MGF_1PADDING);
		String s4 = EncryptUtil.RSA_ENCRYPT.encryptHex("123456", RSAEnum.ECB_OAEP_WITH_SHA256_AND_MGF_1PADDING);
		String s5 = EncryptUtil.RSA_ENCRYPT.encryptHex("123456", RSAEnum.ECB_PKCS1PADDING);
		System.out.println(s3);
		System.out.println(s4);
		System.out.println(s5);
		System.out.println(EncryptUtil.RSA_ENCRYPT.decryptHex(s3, RSAEnum.ECB_OAEP_WITH_SHA1_AND_MGF_1PADDING));
		System.out.println(EncryptUtil.RSA_ENCRYPT.decryptHex(s4, RSAEnum.ECB_OAEP_WITH_SHA256_AND_MGF_1PADDING));
		System.out.println(EncryptUtil.RSA_ENCRYPT.decryptHex(s5, RSAEnum.ECB_PKCS1PADDING));
		
		String s6 = EncryptUtil.RSA_ENCRYPT.encryptHex("123456", "password", null, RSAEnum.ECB_OAEP_WITH_SHA1_AND_MGF_1PADDING);
		String s7 = EncryptUtil.RSA_ENCRYPT.encryptHex("123456", "password", null, RSAEnum.ECB_OAEP_WITH_SHA256_AND_MGF_1PADDING);
		String s8 = EncryptUtil.RSA_ENCRYPT.encryptHex("123456", "password", null, RSAEnum.ECB_PKCS1PADDING);
		System.out.println(s6);
		System.out.println(s7);
		System.out.println(s8);
		System.out.println(EncryptUtil.RSA_ENCRYPT.decryptHex(s6, "password", null, RSAEnum.ECB_OAEP_WITH_SHA1_AND_MGF_1PADDING));
		System.out.println(EncryptUtil.RSA_ENCRYPT.decryptHex(s7, "password", null, RSAEnum.ECB_OAEP_WITH_SHA256_AND_MGF_1PADDING));
		System.out.println(EncryptUtil.RSA_ENCRYPT.decryptHex(s8, "password", null, RSAEnum.ECB_PKCS1PADDING));
	}
}
