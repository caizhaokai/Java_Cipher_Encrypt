package com.github.encrypt.encryptImp;

import org.apache.commons.codec.binary.Base64;

import com.github.encrypt.encryptTypeImpl.HexUtil;

/**
 * 使用MessageDigest进行加密
 */
public abstract class MessageDigestImp <E extends Enum<?>> implements IMessageDigest<E> {
	/**
	 * 配置文件配置的盐
	 */
	protected String configSlat = null;
	/**
	 * 默认加密模式
	 */
	protected E defaultAlgorithm = null;
	
	protected abstract byte[] encrypt(String content, String slat, E encryptType);
	
	@Override
	public String encryptBase64(String content) {
		return encryptBase64(content, configSlat, defaultAlgorithm);
	}

	@Override
	public String encryptBase64(String content, String slat) {
		return encryptBase64(content, slat, defaultAlgorithm);
	}

	@Override
	public String encryptBase64(String content, E encryptType) {
		return encryptBase64(content, configSlat, encryptType);
	}

	@Override
	public String encryptBase64(String content, String slat, E encryptType) {
		byte[] result = encrypt(content, slat, encryptType);
		return Base64.encodeBase64String(result);
	}

	@Override
	public String encryptHex(String content) {
		return encryptHex(content, configSlat, defaultAlgorithm);
	}

	@Override
	public String encryptHex(String content, String slat) {
		return encryptHex(content, slat, defaultAlgorithm);
	}

	@Override
	public String encryptHex(String content, E encryptType) {
		return encryptHex(content, configSlat, encryptType);
	}

	@Override
	public String encryptHex(String content, String slat, E encryptType) {
		byte[] result = encrypt(content, slat, encryptType);
		return HexUtil.byteArrayToHexStr(result);
	}
}
