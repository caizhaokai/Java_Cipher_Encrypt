package com.github.encrypt.EncryptEnum;

public enum ShaEnum {
	SHA1("SHA-1"),
	SHA224("SHA-224"),
	SHA256("SHA-256"),
	SHA384("SHA-384"),
	SHA512("SHA-512");
	
	private ShaEnum(String encryptType) {
		this.encryptType = encryptType;
	}

	private String encryptType;

	public String getEncryptType() {
		return encryptType;
	}

	public void setEncryptType(String encryptType) {
		this.encryptType = encryptType;
	}
}
