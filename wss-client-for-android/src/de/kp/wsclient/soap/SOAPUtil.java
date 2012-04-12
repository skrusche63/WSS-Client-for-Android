package de.kp.wsclient.soap;

import java.util.HashMap;

import org.w3c.dom.Node;

import de.kp.wsclient.security.SecConstants;
import de.kp.wsclient.security.SecCredentialInfo;
import de.kp.wsclient.security.SecCrypto;
import de.kp.wsclient.security.SecCryptoParams;

public class SOAPUtil {

	// this is a helper method to create a new SOAP message
	public static SOAPMessage createSOAPMessage(SecCredentialInfo credentialInfo) {
		return new SOAPMessage(credentialInfo);		
	}

	public static SOAPMessage createSOAPMessage(SecCredentialInfo credentialInfo, Node content) throws Exception {

		SOAPMessage message = createSOAPMessage(credentialInfo);
		message.setContent(content);
		
		return message;
		
	}

	public static SOAPMessage secureSOAPMessage(SOAPMessage message, HashMap<String,String> params, SecCrypto crypto) throws Exception {
		
		if (params.containsKey(SecConstants.REQ_SIGN) && params.get(SecConstants.REQ_SIGN).equals("yes")) {
			// security is restricted to message integrity 
			message.sign();
			
		} else if (params.containsKey(SecConstants.REQ_ENCRYPT_SIGN) && params.get(SecConstants.REQ_ENCRYPT_SIGN).equals("yes")) {
			// security comprises message integrity & confidentiality
			if (crypto == null) throw new Exception("[SOAPMessenger] No crypto information provided.");
			message.encryptAndSign(crypto);
		}
		
		return message;
	}
	
	public static SOAPMessage validateSOAPMessage(SOAPMessage message, HashMap<String,String> params, SecCrypto crypto) throws Exception {
		
		if (params.containsKey(SecConstants.RES_VERIFY) && params.get(SecConstants.RES_VERIFY).equals("yes")) {
			// verify signature of incomig SOAP response message
			message.verify();
			
		} else if (params.containsKey(SecConstants.RES_DECRYPT_VERIFY) && params.get(SecConstants.RES_DECRYPT_VERIFY).equals("yes")) {
			// verify and decrypt incoming SOAP response message
			if (crypto == null) throw new Exception("[SOAPMessenger] No crypto information provided.");
			message.verifyAndDecrypt(crypto);

		}

		return message;
	}
	
	public static SOAPMessage sendSOAPMessage(SOAPMessage message, String endpoint, SecCryptoParams cryptoParams) throws Exception {
		
		SOAPMessenger messenger = SOAPMessenger.getInstance();
		messenger.init(cryptoParams);
		return messenger.sendRequest(message, endpoint);
		
	}

}
