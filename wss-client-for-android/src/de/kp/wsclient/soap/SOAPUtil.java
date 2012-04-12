package de.kp.wsclient.soap;

import java.util.HashMap;

import org.w3c.dom.Node;

import android.content.Context;

import de.kp.wsclient.security.SecCredentialInfo;
import de.kp.wsclient.security.SecCrypto;

public class SOAPUtil {

	// this is a helper method to build a credential info instance from
	// the user's alias & password
	
	public static SecCredentialInfo getCredentialInfo(Context context, String alias, String password) {
		return new SecCredentialInfo(context, alias, password);
	}
	
	// this is a helper method to create a new SOAP message
	public static SOAPMessage createSOAPMessage(SecCredentialInfo credentialInfo) {
		return new SOAPMessage(credentialInfo);		
	}

	public static SOAPMessage createSOAPMessage(SecCredentialInfo credentialInfo, Node content) throws Exception {

		SOAPMessage message = createSOAPMessage(credentialInfo);
		message.setContent(content);
		
		return message;
		
	}

	public static Node sendSOAPMessage(SecCredentialInfo credentialInfo, Node content, String endpoint, HashMap<String,String> params, SecCrypto crypto) throws Exception {

		SOAPMessage message = createSOAPMessage(credentialInfo);
		message.setContent(content);
		
		SOAPMessenger messenger = new SOAPMessenger(credentialInfo);
		messenger.sendRequest(message, endpoint, params, crypto);
		
		return messenger.getResultContent();
		
	}

}
