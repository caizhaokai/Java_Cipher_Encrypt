package com.github.encrypt.encryptTypeImpl;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.github.encrypt.EncryptUtil;
import com.github.encrypt.EncryptEnum.ShaEnum;
import com.github.encrypt.encryptImp.MessageDigestImp;

/**
 * SHA摘要加密
 */
public class ShaUtil extends MessageDigestImp<ShaEnum>{
	public ShaUtil(ShaEnum defaultEncrypt) {
		this.defaultAlgorithm = defaultEncrypt == null ? ShaEnum.SHA256 : defaultEncrypt;
		this.configSlat = EncryptUtil.SHA_SLAT;
	}
//	private final static Logger logger = LoggerFactory.getLogger(ShaUtil.class);
	
	@Override
	protected byte[] encrypt(String content, String slat, ShaEnum encryptType) {
		try {
			String encryptContent = content + slat;
			MessageDigest messageDigest = MessageDigest.getInstance(encryptType.getEncryptType());
			return messageDigest.digest(encryptContent.getBytes());
		} catch (NoSuchAlgorithmException e) {
//			logger.error("Sha MessageDigest init error, encrypt type no support.");
		}
		return null;
	}
}
