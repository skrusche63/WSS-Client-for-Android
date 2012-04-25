package de.kp.wsclient.security;

public class SecConstants {

	// request parameters
	
	public static String REQ_SIGN 		  	= "reqSign";
	public static String REQ_ENCRYPT_SIGN 	= "reqEncryptSign";
	public static String RES_VERIFY       	= "resVerify";
	public static String RES_DECRYPT_VERIFY = "resDecryptVerify";
	
    // namespaces	
	
	/*
	 * Key Transport algorithms are public key encryption algorithms especially specified for 
	 * encrypting and decrypting keys. Their identifiers appear as Algorithm attributes to 
	 * EncryptionMethod elements that are children of EncryptedKey. EncryptedKey is in turn 
	 * the child of a ds:KeyInfo element. The type of key being transported, that is to say 
	 * the algorithm in which it is planned to use the transported key, is given by the Algorithm 
	 * attribute of the EncryptionMethod child of the EncryptedData or EncryptedKey parent of 
	 * this ds:KeyInfo element.
	 * 
	 * Key Transport algorithms may optionally be used to encrypt data in which case they appear 
	 * directly as the Algorithm attribute of an EncryptionMethod child of an EncryptedData element. 
	 * Because they use public key algorithms directly, Key Transport algorithms are not efficient 
	 * for the transport of any amounts of data significantly larger than symmetric keys. 
	 */

    public static final String KEYTRANSPORT_RSA15  = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
    public static final String KEYTRANSPORT_RSAOEP = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";

    public static final String AES_128     = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
    public static final String AES_256 	   = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
    public static final String AES_192 	   = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
    
    public static final String AES_128_GCM = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
    public static final String AES_192_GCM = "http://www.w3.org/2009/xmlenc11#aes192-gcm";
    public static final String AES_256_GCM = "http://www.w3.org/2009/xmlenc11#aes256-gcm";

	public static final String SOAPSEC_NS 				= "http://docs.oasisopen.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0";	
    public static final String WSSE_NS 					= "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"; 
    public static final String WSSE11_NS 				= "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd";
    public static final String WSU_NS  					= "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";   
    public static final String SOAP_MESSAGE_NS11 		= "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1";

    public static final String SIG_NS 					= "http://www.w3.org/2000/09/xmldsig#";
    public static final String ENC_NS 					= "http://www.w3.org/2001/04/xmlenc#";

    public static final String URI_SOAP11_ENV 			= "http://schemas.xmlsoap.org/soap/envelope/";
    public static final String URI_SOAP12_ENV        	= "http://www.w3.org/2003/05/soap-envelope";
    public static final String URI_SOAP11_NEXT_ACTOR    = "http://schemas.xmlsoap.org/soap/actor/next";
    public static final String URI_SOAP12_NEXT_ROLE 	= "http://www.w3.org/2003/05/soap-envelope/role/next";
    public static final String URI_SOAP12_NONE_ROLE 	= "http://www.w3.org/2003/05/soap-envelope/role/none";
    public static final String URI_SOAP12_ULTIMATE_ROLE = "http://www.w3.org/2003/05/soap-envelope/role/ultimateReceiver";

    public static final String X509TOKEN_NS 			= "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0";
    public static final String XMLNS_NS 				= "http://www.w3.org/2000/xmlns/";

    // prefix
    public static final String ENC_PRE  	= "xenc";
    public static final String SIG_PRE  	= "ds";
    public static final String SOAP_PRE 	= "soap";
    public static final String WSSE_PRE 	= "wsse";
    public static final String WSU_PRE  	= "wsu";
    public static final String WSSE11_PRE 	= "wsse11";

    // tags
    public static final String BINARY_TOKEN_LN 			= "BinarySecurityToken";
    public static final String KEYINFO_LN 				= "KeyInfo";
    public static final String REFERENCE                = "Reference";
	public static final String SECURITY_TOKEN_REFERENCE = "SecurityTokenReference";
	public static final String SIGNATURE                = "Signature";
	public static final String SECURITY                 = "Security";
    public static final String ENCRYPTED_HEADER 		= "EncryptedHeader";

    public static final String ENC_KEY_VALUE_TYPE 		= "EncryptedKey";
    public static final String ENC_KEY_SHA1_URI 		= "EncryptedKeySHA1";

    public static final String THUMBPRINT 				= "ThumbprintSHA1";
    public static final String TOKEN_TYPE 				= "TokenType";


    public static final String ATTR_ACTOR    = "actor";
    public static final String ATTR_ROLE     = "role";
    public static final String ELEM_BODY 	 = "Body";
    public static final String ELEM_ENVELOPE = "Envelope";
    public static final String ELEM_HEADER 	 = "Header";

	
    public static final String BST_BASE64_ENCODING = SOAPSEC_NS + "#Base64Binary";
    public static final String BST_VALUE_TYPE      = X509TOKEN_NS +"#X509v3";
    
    public static final String SENDER_CERT = "urn:oasis:names:tc:ebxml-regrep:rs:security:SenderCert";
    public static final String C14N_EXCL_OMIT_COMMENTS = "http://www.w3.org/2001/10/xml-exc-c14n#";

    public static final String WSS_ENC_KEY_VALUE_TYPE = SOAP_MESSAGE_NS11 + "#" + ENC_KEY_VALUE_TYPE;

    // constants from WSS4J
    public static final int BST_DIRECT_REFERENCE     	  = 1;
    public static final int ISSUER_SERIAL 		 	 	  = 2; // NOT SUPPORTED
    public static final int X509_KEY_IDENTIFIER  	      = 3;
    public static final int SKI_KEY_IDENTIFIER   	 	  = 4;
    public static final int EMBEDDED_KEYNAME     	 	  = 5;
    public static final int EMBED_SECURITY_TOKEN_REF 	  = 6;
    public static final int UT_SIGNING 					  = 7;
    public static final int THUMBPRINT_IDENTIFIER 		  = 8;
    public static final int CUSTOM_SYMM_SIGNING 		  = 9;
    public static final int ENCRYPTED_KEY_SHA1_IDENTIFIER = 10;
    public static final int CUSTOM_SYMM_SIGNING_DIRECT 	  = 11;
    public static final int CUSTOM_KEY_IDENTIFIER 		  = 12;
    public static final int KEY_VALUE 					  = 13;

    /*
     * KEYSTORE FORMAT
     */
    
    public static String KS_TYPE_BKS    = "BKS";
    public static String KS_TYPE_PKCS11 = "PKCS11";
    
}
