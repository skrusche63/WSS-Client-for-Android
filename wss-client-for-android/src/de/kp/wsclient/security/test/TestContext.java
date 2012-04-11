package de.kp.wsclient.security.test;

import java.security.PrivateKey;
import java.util.Arrays;

public class TestContext {

	private static TestContext instance = new TestContext();
	
	private byte[] SecEncryptor_cipherValue;
	private byte[] SecDecryptor_cipherValue;
	
	private PrivateKey privateKey;
	
	private TestContext() {
		
	}
	
	public static TestContext getInstance() {
		if (instance == null) instance = new TestContext();
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
