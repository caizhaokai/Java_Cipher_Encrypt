package com.github.encrypt.encryptImp;

/**
 * MessageDigest加密的接口
 */
public interface IMessageDigest<E extends Enum<?>> {
	String encryptBase64(String content);
	String encryptBase64(String content, String slat);
	String encryptBase64(String content, E encryptType);
	String encryptBase64(String content, String slat, E encryptType);
	
	String encryptHex(String content);
	String encryptHex(String content, String slat);
	String encryptHex(String content, E encryptType);
	String encryptHex(String content, String slat, E encryptType);
}
