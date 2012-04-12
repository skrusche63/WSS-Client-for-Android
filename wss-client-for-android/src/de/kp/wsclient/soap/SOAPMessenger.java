package de.kp.wsclient.soap;

import java.io.InputStream;
import java.util.HashMap;

import org.w3c.dom.Node;

import de.kp.wsclient.security.SecConstants;
import de.kp.wsclient.security.SecCrypto;

public class SOAPMessenger {

	private SOAPSenderImpl soapSender;
	private SOAPMessage resultMessage;
	
	public SOAPMessenger() {
		this.soapSender = new SOAPSenderImpl();
	}
	
	public void sendRequest(SOAPMessage message, String endpoint, HashMap<String, String> params, SecCrypto crypto) throws Exception {

		if (params.containsKey(SecConstants.REQ_SIGN) && params.get(SecConstants.REQ_SIGN).equals("yes")) {
			// security is restricted to message integrity 
			message.sign();
			
		} else if (params.containsKey(SecConstants.REQ_ENCRYPT_SIGN) && params.get(SecConstants.REQ_ENCRYPT_SIGN).equals("yes")) {
			// security comprises message integrity & confidentiality
			if (crypto == null) throw new Exception("[SOAPMessenger] No crypto information provided.");
			message.encryptAndSign(crypto);
			
		}
		
		SOAPResponse soapResponse = null;
			
		// send SOAP message to web service identified by its url
		soapResponse = this.soapSender.doSoapRequest(message, endpoint);
		
		int httpStatus = soapResponse.getHttpStatus();
		if (httpStatus == 200) {
		
			InputStream data = soapResponse.getData();
			if (data == null) throw new Exception("No response data retrieved.");
			
			resultMessage = new SOAPMessage(data);

			if (params.containsKey(SecConstants.RES_VERIFY) && params.get(SecConstants.RES_VERIFY).equals("yes")) {
				// verify signature of incomig SOAP response message
				resultMessage.verify();
				
			} else if (params.containsKey(SecConstants.RES_DECRYPT_VERIFY) && params.get(SecConstants.RES_DECRYPT_VERIFY).equals("yes")) {
				// verify and decrypt incoming SOAP response message
				if (crypto == null) throw new Exception("[SOAPMessenger] No crypto information provided.");
				resultMessage.verifyAndDecrypt(crypto);

			}
			
		}
		
	}

	public Node getResultContent() throws Exception {
		
		if (this.resultMessage == null) throw new Exception("No result message retrieved.");
		return this.resultMessage.getContent();
	
	}
	
}
