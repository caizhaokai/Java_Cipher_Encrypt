package com.github.encrypt.EncryptEnum;

public enum MDEnum {
	MD2("MD2"),
	MD5("MD5");
	
	private MDEnum(String encryptType) {
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
