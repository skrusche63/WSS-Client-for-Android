package de.kp.wsclient.soap;

import org.w3c.dom.Node;

import de.kp.wsclient.security.SecCredentialInfo;

public class SOAPUtil {

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
