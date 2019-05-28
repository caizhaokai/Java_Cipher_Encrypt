package com.github.encrypt.encryptTypeImpl;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

import com.github.encrypt.EncryptUtil;
import com.github.encrypt.EncryptEnum.AseEnum;
import com.github.encrypt.encryptImp.CipherEencryptImp;


/**
 * AES加密实现，key使用类KeyGenerator获取，与使用new SecretKeySpec()获取key的优点是传入的key长度可以是任意的，不需要固定16位byte
 * 
 * 若出现 异常：Given final block not properly padded. Such issues can arise if a bad key is used during decryption.
 * 属于解密失败，原因可能是传入的slatKey或者vectorKey与加密时使用的不一致
 */
public class AesKgenUtil extends CipherEencryptImp<AseEnum> {
	public AesKgenUtil(AseEnum defaultEncrypt) {
		this.defaultAlgorithm = defaultEncrypt == null ? AseEnum.CBC_NO_PADDING : defaultEncrypt;
		this.configSlat = EncryptUtil.AES_SLAT;
		this.configVectorKey = EncryptUtil.AES_SLAT;
	}

//	private final static Logger logger = LoggerFactory.getLogger(AesKgenUtil.class);
	private final static String AES_ALGORITHM_NAME = "AES";
	private final static String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";
	private final static int SLAT_KEY_LENGTH = 128;
	private final static int VECTOR_KEY_LENGTH = 128;

	@Override
	protected byte[] encrypt(String content, String slatKey, String vectorKey, AseEnum encryptType) throws Exception {
		byte[] encrypted = null;
		try {
			if (slatKey == null) 
			{
				throw new Exception("slatKey is null");
			}
			if (encryptType == null) 
			{
				throw new Exception("encryptType is null");
			}
			Cipher cipher = Cipher.getInstance(encryptType.getEncryptType());
			Key key = getSlatKey(slatKey);
			byte[] plaintext = null;
			if (AseEnum.CBC_NO_PADDING.equals(encryptType) || AseEnum.ECB_NO_PADDING.equals(encryptType)) 
			{
				plaintext = handleNoPaddingEncryptFormat(cipher, content);
			} else {
				plaintext = content.getBytes();
			}
			if (AseEnum.CBC_NO_PADDING.equals(encryptType) || AseEnum.CBC_PKCS5PADDING.equals(encryptType))
			{
				if (vectorKey == null) 
				{
					throw new Exception("vectorKey is null");
				}
				IvParameterSpec iv = getVectorKey(vectorKey);
				cipher.init(Cipher.ENCRYPT_MODE, key, iv);
			} 
			else 
			{
				cipher.init(Cipher.ENCRYPT_MODE, key);
			}
			encrypted = cipher.doFinal(plaintext);
		} catch (Exception e) {
//			logger.error("Aes Util encryption failed, errors: {}", e.getMessage());
			throw new Exception(encryptException);
		}
		return encrypted;
	}

	@Override
	protected String decrypt(byte[] content, String slatKey, String vectorKey, AseEnum encryptType) throws Exception {
		String result = null;
		try {
			if (slatKey == null) 
			{
				throw new Exception("slatKey is null");
			}
			if (encryptType == null) 
			{
				throw new Exception("encryptType is null");
			}
			Cipher cipher = Cipher.getInstance(encryptType.getEncryptType());
			Key key = getSlatKey(slatKey);
			if (AseEnum.CBC_NO_PADDING.equals(encryptType) || AseEnum.CBC_PKCS5PADDING.equals(encryptType)) 
			{
				if (vectorKey == null) 
				{
					throw new Exception("vectorKey is null");
				}
				IvParameterSpec iv = getVectorKey(vectorKey);
				cipher.init(Cipher.DECRYPT_MODE, key, iv);
			}
			else 
			{
				cipher.init(Cipher.DECRYPT_MODE, key);
			}
			byte[] original = cipher.doFinal(content);
			result = new String(original).trim();
		} catch (Exception e) {
//			logger.error("Aes Util decryption failed, errors: {}", e.getMessage());
			throw new Exception(decryptException);
		}
		return result;
	}

	/**
	 * 获取加密的密匙，传入的slatKey可以是任意长度的，作为SecureRandom的随机种子，
	 * 而在KeyGenerator初始化时设置密匙的长度128bit(16位byte)
	 */
	private static Key getSlatKey(String slatKey) throws Exception {
		KeyGenerator kgen = KeyGenerator.getInstance(AES_ALGORITHM_NAME);
		SecureRandom random = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM);
		random.setSeed(slatKey.getBytes());
		kgen.init(SLAT_KEY_LENGTH, random);
		Key key = kgen.generateKey();
		return key;
	}

	/**
	 * 获取加密的向量
	 */
	private static IvParameterSpec getVectorKey(String vectorKey) throws Exception {
		KeyGenerator kgen = KeyGenerator.getInstance(AES_ALGORITHM_NAME);
		SecureRandom random = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM);
		random.setSeed(vectorKey.getBytes());
		kgen.init(VECTOR_KEY_LENGTH, random);
		IvParameterSpec iv = new IvParameterSpec(kgen.generateKey().getEncoded());
		return iv;
	}
}
