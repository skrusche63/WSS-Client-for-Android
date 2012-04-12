package de.kp.wsclient.security;

import java.util.HashMap;

public class SecCryptoParams extends HashMap<String, SecCryptoParam> {

	private static final long serialVersionUID = -4038677369216443458L;

	/** key to identify a keystore param **/
	public static final String KEYSTORE = "KEYSTORE";
	
	/** key to identify a truststore param **/
	public static final String TRUSTSTORE = "TRUSTSTORE";
	
}
