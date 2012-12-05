package de.kp.wsclient.soap;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import android.content.Context;

import de.kp.wsclient.security.SecCryptoParams;

public class SOAPMessenger {

	private SOAPSenderImpl soapSender;
	private boolean initialized;
	
	private static SOAPMessenger instance = new SOAPMessenger();
	
	private SOAPMessenger() {}
	
	public static SOAPMessenger getInstance() {
		if (instance == null) instance = new SOAPMessenger();
		return instance;
	}
	
	public void init(Context context, SecCryptoParams cryptoParams) throws Exception {

		/*
		 * The SOAPSenderImpl is initialized only once
		 */
		if (initialized == false) {
			this.soapSender = new SOAPSenderImpl(context);
			this.soapSender.init(cryptoParams);
		}
		
		initialized = true;
	}
	
	/**
	 * @param message
	 * @param endpoint
	 * @return
	 * @throws Exception
	 */
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
	
}
