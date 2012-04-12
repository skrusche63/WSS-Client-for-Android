package de.kp.wsclient.security;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class SecCredentialInfo {

	private X509Certificate certificate;
	private PrivateKey privateKey;
	
	
	public SecCredentialInfo(X509Certificate certificate, PrivateKey privateKey) {
		this.certificate = certificate;
		this.privateKey = privateKey;
		
	}
	
	public PrivateKey getPrivateKey() {
		return this.privateKey;
	}
	
	public X509Certificate getCertificate() {
		return this.certificate;
	}
	
}
