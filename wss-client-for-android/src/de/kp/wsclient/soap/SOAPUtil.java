package de.kp.wsclient.soap;

import org.w3c.dom.Node;

import android.content.Context;

import de.kp.wsclient.security.SecCredentialInfo;

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

	public static Node sendSOAPMessage(SecCredentialInfo credentialInfo, Node content, String endpoint) throws Exception {

		SOAPMessage message = createSOAPMessage(credentialInfo);
		message.setContent(content);
		
		SOAPMessenger messenger = new SOAPMessenger();
		messenger.sendRequest(message, endpoint);
		
		return messenger.getResultContent();
		
	}

}
