![Dr. Krusche & Partner](https://raw.githubusercontent.com/skrusche63/WSS-Client-for-Android/master/wss-client-for-android/images/dr_kruscheundpartner_640.png)

## Web Service Security for Android

This project brings the SOAP protocol (Simple Object Access Protocol) and Web Service Security (WSS) Android platforms. WSS-Client for Android makes it possible to securely access web services from the mobile sector.

The image below describes WSS-Client for Android in the context of e.g. an e-commerce environment. 

![WSS-Client for Android Overview](https://raw.githubusercontent.com/skrusche63/WSS-Client-for-Android/master/wss-client-for-android/images/wss_client_overview_640.png)

### Web Service Security

**WSS-Client for Android** implements the OASIS Web Service Security (WSS) standard for Android platforms and makes **XML Encryption** and **XML Signature** 
available for tablets and smartphones.
            
**XML Signature** describes an XML syntax for digital signatures and is defined in the W3C recommendation "XML Signature Syntax and Processing". Signing a certain information
ensures information integrity and protects against falsification. A digital signature may also be used to uniquely determine the digital identity of a certain user, which is a 
trustworthy basis for further access control mechanisms.
            
**XML Encryption** is a specification that is governed by a W3C recommendation and defines how to encryt the content of an XML element. An XML element in this context is either an XML message as a whole or selected parts of a message. This makes it even more flexible to adequately respond to the security needs of enterprise data.            

Web Service Security secures data and ensures integrity. It guarantees end-to-end security and is independent of the security mechanism provided by the transport layer. It is a must for a secure shopping experience.

![Message Layer Security](https://raw.githubusercontent.com/skrusche63/WSS-Client-for-Android/master/wss-client-for-android/images/message_security_640.png)


---

### SOAP Messenger

**SOAP Messenger** is a key component to access SOAP based web services from tablets and smartphones. With this component, mobile devices are enabled to seamlessly integrate with Software as a Service. The SOAP messenger module provides the basis for a secure message exchange, and, combined with WSS overcomes the well-known security issues on the transport level.

The class ```SOAPMessenger```is the starting point to either understand the functionality of WSS-Client for Android or directly integrate into the specific application logic.

```
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
```

---

### PKCS#11
           
**PKCS#11** is a member of the Public-Key Cryptography Standards (PKCS) family. It defines a platform-independent interfaces to Hardware Security Modules such 
as smartcards. WSS-Client for Android supports this standard und grants access to the user's smartcard to read his public also private key to secure the SOAP 
based communication.

###PKCS#12

**PKCS#12** is another member of the Public-Key Cryptography Standards family, that is supported by WSS-Client for Android. This standard defines a file 
format, that is used to store the private key and digital certificate (X.509) of a certain user.
