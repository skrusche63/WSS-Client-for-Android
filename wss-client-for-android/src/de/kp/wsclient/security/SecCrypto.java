package de.kp.wsclient.security;

import java.security.PrivateKey;
import java.security.PublicKey;

public class SecCrypto {

	private PrivateKey privateKey;
	private PublicKey publicKey;
	
	public SecCrypto(PublicKey publicKey, PrivateKey privateKey) {
	
		this.publicKey = publicKey;
		this.privateKey = privateKey;
		
	}
	
	public PrivateKey getPrivateKey() {
		return this.privateKey;
	}
	
	public PublicKey getPublicKey() {
		return this.publicKey;
	}
	
}
