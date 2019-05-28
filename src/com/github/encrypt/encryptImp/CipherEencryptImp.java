package com.github.encrypt.encryptImp;

import java.nio.charset.Charset;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;

import com.github.encrypt.encryptTypeImpl.HexUtil;

/**
 * 使用Cipher进行加密
 */
public abstract class CipherEencryptImp<E extends Enum<?>> implements ICipherEncrypt<E>{
	/**
	 * 若加密失败, 抛出该异常信息
	 */
	protected static final String encryptException = "Encrypt Error!";
	/**
	 * 若解密失败, 抛出该异常信息
	 */
	protected static final String decryptException = "Decrypt Error!";
	/**
	 * 配置文件配置的盐
	 */
	protected String configSlat = null;
	/**
	 * 配置文件配置的向量
	 */
	protected String configVectorKey = null;
	/**
	 * 默认加密模式
	 */
	protected E defaultAlgorithm = null;
	
	/**
	 * 加密, 若直接将返回结果转为String类型, 为乱码, 可以转为Base64或转为16进制
	 * @param content   : 加密内容
	 * @param slatKey   : 加密的盐
	 * @param vectorKey : 加密向量
	 * @param encryptType : 加密模式
	 * @return 密文(byte[])
	 * @throws Exception 
	 */
	protected abstract byte[] encrypt(String content, String slatKey, String vectorKey, E encryptType) throws Exception;
	/**
	 * 解密
	 * @param content   : 解密内容
	 * @param slatKey   : 解密的盐
	 * @param vectorKey : 解密向量
	 * @param encryptType : 解密模式
	 * @return 明文密码(String)
	 * @throws Exception 
	 */
	protected abstract String decrypt(byte[] content, String slatKey, String vectorKey, E encryptType) throws Exception;
	
	protected static byte[] handleNoPaddingEncryptFormat(Cipher cipher, String content) throws Exception {
		return handleNoPaddingEncryptFormat(cipher, content, Charset.defaultCharset());
	}
	
	/**
	 * <p>NoPadding加密模式, 加密内容必须是 8byte的倍数, 不足8位则末位补足0</p>
	 * <p>加密算法不提供该补码方式, 需要代码完成该补码方式</p>
	 * @param cipher
	 * @param content ：加密内容
	 * @Param charset :指定的字符集
	 * @return 符合加密的内容(byte[])
	 */
	protected static byte[] handleNoPaddingEncryptFormat(Cipher cipher, String content, Charset charset) throws Exception {
		int blockSize = cipher.getBlockSize();
		byte[] srawt = content.getBytes(charset);
		int plaintextLength = srawt.length;
		if (plaintextLength % blockSize != 0) {
			plaintextLength = plaintextLength + (blockSize - plaintextLength % blockSize);
		}
		byte[] plaintext = new byte[plaintextLength];
		System.arraycopy(srawt, 0, plaintext, 0, srawt.length);
		return plaintext;
	}
	
	@Override
	public String encryptBase64(String content) throws Exception {
		return encryptBase64(content, configSlat, configVectorKey, defaultAlgorithm);
	}
	@Override
	public String decryptBase64(String content) throws Exception {
		return decryptBase64(content, configSlat, configVectorKey, defaultAlgorithm);
	}
	@Override
	public String encryptBase64(String content, String slatKey, String vectorKey) throws Exception {
		return encryptBase64(content, slatKey, vectorKey, defaultAlgorithm);
	}
	@Override
	public String decryptBase64(String content, String slatKey, String vectorKey) throws Exception {
		return decryptBase64(content, slatKey, vectorKey, defaultAlgorithm);
	}
	@Override
	public String encryptBase64(String content, E encryptType) throws Exception {
		return encryptBase64(content, configSlat, configVectorKey, encryptType);
	}
	@Override
	public String decryptBase64(String content, E encryptType) throws Exception {
		return decryptBase64(content, configSlat, configVectorKey, encryptType);
	}
	@Override
	public String encryptBase64(String content, String slatKey, String vectorKey, E encryptType) throws Exception {
		byte[] result = encrypt(content, slatKey, vectorKey, encryptType);
		return Base64.encodeBase64String(result);
	}
	@Override
	public String decryptBase64(String content, String slatKey, String vectorKey, E encryptType) throws Exception {
		byte[] byteContent = Base64.decodeBase64(content);
		return decrypt(byteContent, slatKey, vectorKey, encryptType);
	}
	@Override
	public String encryptHex(String content) throws Exception {
		return encryptHex(content, configSlat, configVectorKey, defaultAlgorithm);
	}
	@Override
	public String decryptHex(String content) throws Exception {
		return decryptHex(content, configSlat, configVectorKey, defaultAlgorithm);
	}
	@Override
	public String encryptHex(String content, String slatKey, String vectorKey) throws Exception {
		return encryptHex(content, slatKey, vectorKey, defaultAlgorithm);
	}
	@Override
	public String decryptHex(String content, String slatKey, String vectorKey) throws Exception {
		return decryptHex(content, slatKey, vectorKey, defaultAlgorithm);
	}
	@Override
	public String encryptHex(String content, E encryptType) throws Exception {
		return encryptHex(content, configSlat, configVectorKey, encryptType);
	}
	@Override
	public String decryptHex(String content, E encryptType) throws Exception {
		return decryptHex(content, configSlat, configVectorKey, encryptType);
	}
	@Override
	public String encryptHex(String content, String slatKey, String vectorKey, E encryptType) throws Exception {
		byte[] result = encrypt(content, slatKey, vectorKey, encryptType);
		return HexUtil.byteArrayToHexStr(result);
	}
	@Override
	public String decryptHex(String content, String slatKey, String vectorKey, E encryptType) throws Exception {
		byte[] byteContent = HexUtil.hexStrToByteArray(content);
		return decrypt(byteContent, slatKey, vectorKey, encryptType);
	}
}
