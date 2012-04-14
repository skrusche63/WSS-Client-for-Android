package de.kp.wsclient.security;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class SecCrypto {

	private PrivateKey privateKey;
	private PublicKey publicKey;

	private X509Certificate certificate;

	public SecCrypto(X509Certificate certificate, PrivateKey privateKey) {
		
		this.certificate = certificate;
		
		this.publicKey  = certificate.getPublicKey();
		this.privateKey = privateKey;
		
	}
	
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

	public X509Certificate getCertificate() {
		return this.certificate;
	}
}
