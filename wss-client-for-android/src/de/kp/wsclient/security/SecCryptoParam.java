package de.kp.wsclient.security;

/**
 * This is a wrapper class to provide access to a certain 
 * keystore resource on an android platform
 * 
 * @author Peter Arwanitis (arwanitis@dr-kruscheundpartner.de)
 *
 */

public class SecCryptoParam {

	private int resource;
	private String password;
	
	// the default keystore is a BouncyCastle keystore
	private String type = SecConstants.KS_TYPE_BKS;
	
	public SecCryptoParam(int resource, String password) {

		this.resource = resource;
		this.password = password;
	}
	
	
	/**
	 * @return
	 */
	public int getResource() {
		return resource;
	}

	/**
	 * @param resource
	 */
	public void setResource(int resource) {
		this.resource = resource;
	}
	
	/**
	 * @return
	 */
	public String getPassword() {
		return password;
	}
	
	/**
	 * @param password
	 */
	public void setPassword(String password) {
		this.password = password;
	}
	
	/**
	 * @return
	 */
	public String getType() {
		return type;
	}
	
	/**
	 * @param type
	 */
	public void setType(String type) {
		this.type = type;
	}
	
	
}
