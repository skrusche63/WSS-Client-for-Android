package de.kp.wsclient.soap;

import java.util.HashMap;

import android.content.Context;

import de.kp.wsclient.security.SecConstants;
import de.kp.wsclient.security.SecCredentialInfo;
import de.kp.wsclient.security.SecCrypto;
import de.kp.wsclient.security.SecCryptoParams;

public class SOAPUtil {

	public static SOAPMessage createSOAPMessage() {
		return new SOAPMessage();		
	}

	public static SOAPMessage secureSOAPMessage(SOAPMessage message, HashMap<String,String> params, SecCredentialInfo credentials, SecCrypto crypto) throws Exception {
		
		if (params.containsKey(SecConstants.REQ_SIGN) && params.get(SecConstants.REQ_SIGN).equals("yes")) {
			// security is restricted to message integrity 
			if (credentials == null) throw new Exception("[SOAPMessenger] No credential information provided.");
			message.sign(credentials);
			
		} else if (params.containsKey(SecConstants.REQ_ENCRYPT_SIGN) && params.get(SecConstants.REQ_ENCRYPT_SIGN).equals("yes")) {
			// security comprises message integrity & confidentiality
			if ((credentials == null) || (crypto == null)) throw new Exception("[SOAPMessenger] No credential or crypto information provided.");
			message.encryptAndSign(credentials, crypto);
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
	
	public static SOAPMessage sendSOAPMessage(Context context, SOAPMessage message, String endpoint, SecCryptoParams cryptoParams) throws Exception {
		
		SOAPMessenger messenger = SOAPMessenger.getInstance();
		// the messenger is initialized only once
		messenger.init(context, cryptoParams);

		return messenger.sendRequest(message, endpoint);
		
	}

}
