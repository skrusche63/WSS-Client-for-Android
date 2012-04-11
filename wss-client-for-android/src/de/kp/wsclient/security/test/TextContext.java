package de.kp.wsclient.security.test;

import java.security.PrivateKey;
import java.util.Arrays;

public class TextContext {

	private static TextContext instance = new TextContext();
	
	private byte[] SecEncryptor_cipherValue;
	private byte[] SecDecryptor_cipherValue;
	
	private PrivateKey privateKey;
	
	private TextContext() {
		
	}
	
	public static TextContext getInstance() {
		if (instance == null) instance = new TextContext();
		return instance;
	}
	
	public void setEncryptorCipherValue(byte[] cipherValue) {
		this.SecEncryptor_cipherValue = cipherValue;
	}

	public void setDecryptorCipherValue(byte[] cipherValue) {
		this.SecDecryptor_cipherValue = cipherValue;
	}
	
	public boolean compareCipherValues() {
		return Arrays.equals(this.SecEncryptor_cipherValue, this.SecDecryptor_cipherValue);
	}
	
	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}
	
	public PrivateKey getPrivateKey() {
		return this.privateKey;
	}
}
