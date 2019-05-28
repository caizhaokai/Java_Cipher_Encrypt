package com.github.encrypt.encryptImp;

/**
 * Cipher类的加密、解密接口
 */
public interface ICipherEncrypt<E extends Enum<?>> {
	String encryptBase64(String content) throws Exception;
	String decryptBase64(String content) throws Exception;
	String encryptBase64(String content, String slatKey, String vectorKey) throws Exception;
	String decryptBase64(String content, String slatKey, String vectorKey) throws Exception;
	String encryptBase64(String content, E encryptType) throws Exception;
	String decryptBase64(String content, E encryptType) throws Exception;
	String encryptBase64(String content, String slatKey, String vectorKey, E encryptType) throws Exception;
	String decryptBase64(String content, String slatKey, String vectorKey, E encryptType) throws Exception;

	String encryptHex(String content) throws Exception;
	String decryptHex(String content) throws Exception;
	String encryptHex(String content, String slatKey, String vectorKey) throws Exception;
	String decryptHex(String content, String slatKey, String vectorKey) throws Exception;
	String encryptHex(String content, E encryptType) throws Exception;
	String decryptHex(String content, E encryptType) throws Exception;
	String encryptHex(String content, String slatKey, String vectorKey, E encryptType) throws Exception;
	String decryptHex(String content, String slatKey, String vectorKey, E encryptType) throws Exception;
}
