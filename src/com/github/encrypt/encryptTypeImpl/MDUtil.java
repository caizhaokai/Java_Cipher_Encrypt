package com.github.encrypt.encryptTypeImpl;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.github.encrypt.EncryptUtil;
import com.github.encrypt.EncryptEnum.MDEnum;
import com.github.encrypt.encryptImp.MessageDigestImp;

/**
 * MD加密工具类
 */
public class MDUtil extends MessageDigestImp<MDEnum>{
	
//	private final static Logger logger = LoggerFactory.getLogger(ShaUtil.class);
	
	public MDUtil(MDEnum defaultEncrypt) {
		this.defaultAlgorithm = defaultEncrypt == null ? MDEnum.MD5 : defaultEncrypt;
		this.configSlat = EncryptUtil.MD_SLAT;
	}
	
	@Override
	protected byte[] encrypt(String content, String slat, MDEnum encryptType) {
		try {
			String encryptContent = null;
			if (slat != null)
			{
				encryptContent = content + slat;
			}
			else
			{
				encryptContent = content;
			}
			MessageDigest messageDigest = MessageDigest.getInstance(encryptType.getEncryptType());
			return messageDigest.digest(encryptContent.getBytes());
		} catch (NoSuchAlgorithmException e) {
//			logger.error("MD MessageDigest init error, encrypt type no support.");
		}
		return null;
	}
}
