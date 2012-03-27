package de.kp.wsclient.security;

public class SecConstants {

    // namespaces
	public static final String SOAPSEC_NS 	= "http://docs.oasisopen.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0";	
    public static final String WSSE_NS 		= "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    public static final String WSU_NS  		= "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";   

    public static final String X509TOKEN_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0";
    public static final String XMLNS_NS 	= "http://www.w3.org/2000/xmlns/";

    // prefix
    public static final String WSSE_PRE = "wsse";
    public static final String WSU_PRE  = "wsu";

    // tags
    public static final String BINARY_TOKEN_LN 			= "BinarySecurityToken";
    public static final String REFERENCE                = "Reference";
	public static final String SECURITY_TOKEN_REFERENCE = "SecurityTokenReference";
	public static final String SIGNATURE                = "Signature";
	public static final String SECURITY                 = "Security";

    public static final String BST_BASE64_ENCODING = SOAPSEC_NS + "#Base64Binary";
    public static final String BST_VALUE_TYPE      = X509TOKEN_NS +"#X509v3";
    
    public static final String SENDER_CERT = "urn:oasis:names:tc:ebxml-regrep:rs:security:SenderCert";

    public static final String C14N_EXCL_OMIT_COMMENTS = "http://www.w3.org/2001/10/xml-exc-c14n#";

}
