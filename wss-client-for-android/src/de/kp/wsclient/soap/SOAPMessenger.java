package de.kp.wsclient.soap;

import java.io.InputStream;

import org.w3c.dom.Node;

public class SOAPMessenger {

	private SOAPSenderImpl soapSender;
	private SOAPMessage resultMessage;
	
	public SOAPMessenger() {
		this.soapSender = new SOAPSenderImpl();
	}
	
	public void sendRequest(SOAPMessage message, String endpoint) throws Exception {

		// sign SOAP message before sending to web service
		message.sign();
		
		SOAPResponse soapResponse = null;
			
		// send SOAP message to web service identified by its url
		soapResponse = this.soapSender.doSoapRequest(message, endpoint);
		
		int httpStatus = soapResponse.getHttpStatus();
		if (httpStatus == 200) {
		
			InputStream data = soapResponse.getData();
			if (data == null) throw new Exception("No response data retrieved.");
			
			resultMessage = new SOAPMessage(data);
			
			// verify incomig SOAP response
			resultMessage.verify();
			
		}
		
	}

	public Node getResultContent() throws Exception {
		
		if (this.resultMessage == null) throw new Exception("No result message retrieved.");
		return this.resultMessage.getContent();
	
	}
	
}
