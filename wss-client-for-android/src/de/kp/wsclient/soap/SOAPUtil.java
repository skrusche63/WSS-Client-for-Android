package de.kp.wsclient.soap;

import java.util.HashMap;

import android.content.Context;

import de.kp.wsclient.security.SecConstants;
import de.kp.wsclient.security.SecCrypto;
import de.kp.wsclient.security.SecCryptoParams;

/**
 * This is a utility class to support secure SOAP communications
 * for android platforms. This is usually done, following these
 * steps
 * 
 * (1) Create SOAP message
 * (2) Secure SOAP message
 * (3) Send SOAP Message
 * (4) Validate SOAP Message (response)
 * 
 * @author Stefan Krusche (krusche@dr-kruscheundpartner.de)
 *
 */
public class SOAPUtil {

	public static SOAPMessage createSOAPMessage() {
		return new SOAPMessage();		
	}

	/**
	 * This method supports signing, and encrypting & signing of
	 * a certain SOAP message;
	 * 
	 * @param message SOAP message to be secured
	 * @param params Configuration parameters to enable encryption / signature
	 * @param credentials User Credentials used to sign a SOAP message
	 * @param crypto Crypto Data used to encrypt a SOAP Message
	 * @return
	 * @throws Exception
	 */
	public static SOAPMessage secureSOAPMessage(SOAPMessage message, HashMap<String,String> params, SecCrypto sigCrypto, SecCrypto encCrypto) throws Exception {
		
		if (params.containsKey(SecConstants.REQ_SIGN) && params.get(SecConstants.REQ_SIGN).equals("yes")) {
			if (sigCrypto == null) throw new Exception("[SOAPMessenger] No credential information provided.");
			message.sign(sigCrypto);
			
		} else if (params.containsKey(SecConstants.REQ_ENCRYPT_SIGN) && params.get(SecConstants.REQ_ENCRYPT_SIGN).equals("yes")) {
			if ((sigCrypto == null) || (encCrypto == null)) throw new Exception("[SOAPMessenger] No credential or crypto information provided.");
			message.encryptAndSign(sigCrypto, encCrypto);
		}
		
		return message;
	}
	
	/**
	 * @param message
	 * @param params
	 * @param crypto
	 * @return
	 * @throws Exception
	 */
	public static SOAPMessage validateSOAPMessage(SOAPMessage message, HashMap<String,String> params, SecCrypto decCrypto) throws Exception {
		
		if (params.containsKey(SecConstants.RES_VERIFY) && params.get(SecConstants.RES_VERIFY).equals("yes")) {
			message.verify();
			
		} else if (params.containsKey(SecConstants.RES_DECRYPT_VERIFY) && params.get(SecConstants.RES_DECRYPT_VERIFY).equals("yes")) {
			if (decCrypto == null) throw new Exception("[SOAPMessenger] No crypto information provided.");
			message.verifyAndDecrypt(decCrypto);

		}

		return message;
	}
	
	/**
	 * @param context
	 * @param message
	 * @param endpoint
	 * @param cryptoParams
	 * @return
	 * @throws Exception
	 */
	public static SOAPMessage sendSOAPMessage(Context context, SOAPMessage message, String endpoint, SecCryptoParams cryptoParams) throws Exception {
		
		SOAPMessenger messenger = SOAPMessenger.getInstance();
		// the messenger is initialized only once
		messenger.init(context, cryptoParams);

		return messenger.sendRequest(message, endpoint);
		
	}


}
