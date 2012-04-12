package de.kp.wsclient.soap;

import java.io.InputStream;

import org.w3c.dom.Node;

import de.kp.wsclient.security.SecCryptoParam;
import de.kp.wsclient.security.SecCryptoParams;

public class SOAPMessenger {

	private SOAPSenderImpl soapSender;
	private SOAPMessage resultMessage;
	private boolean initialized;
	
	private static SOAPMessenger instance = new SOAPMessenger();
	
	private SOAPMessenger() {}
	
	public static SOAPMessenger getInstance() {
		if (instance == null) instance = new SOAPMessenger();
		return instance;
	}
	
	public void init(SecCryptoParams cryptoParams) throws Exception {
		if (initialized == false) {
			this.soapSender = new SOAPSenderImpl();
			this.soapSender.init(cryptoParams);
		}
		
		initialized = true;
	}
	
	public SOAPMessage sendRequest(SOAPMessage message, String endpoint) throws Exception {
		if (initialized == false)
			throw new Exception("[SOAPMessenger] Is not initialized");

		SOAPMessage responseMessage = null;
			
		// send SOAP message to web service identified by its url
		SOAPResponse soapResponse = this.soapSender.doSoapRequest(message, endpoint);
		
		int httpStatus = soapResponse.getHttpStatus();
		if (httpStatus == 200) {
		
			InputStream data = soapResponse.getData();
			if (data == null) throw new Exception("No response data retrieved.");
			
			responseMessage = new SOAPMessage(data);

			
		}
		
		return responseMessage;
	}

	public Node getResultContent() throws Exception {
		
		if (this.resultMessage == null) throw new Exception("No result message retrieved.");
		return this.resultMessage.getContent();
	
	}
	
}
