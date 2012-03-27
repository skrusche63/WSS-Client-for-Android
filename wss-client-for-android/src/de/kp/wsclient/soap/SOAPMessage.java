package de.kp.wsclient.soap;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import de.kp.wsclient.security.SecCredentialInfo;
import de.kp.wsclient.security.SecSignature;
import de.kp.wsclient.security.SecValidator;
import de.kp.wsclient.xml.XMLSerializer;

public class SOAPMessage {

	private Document xmlDoc;
	
	private Element header;
	private Element body;
	
	private String bodyId = "TheBody";
	
	private SecCredentialInfo credentialInfo;
	
	// this constructor is used to build a new SOAP message;
	// use case: outgoing SOAP message
	
	public SOAPMessage(SecCredentialInfo credentialInfo) {
		
		this.credentialInfo = credentialInfo;
		
	    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	    factory.setNamespaceAware(true);
	    
	    try {

	    	xmlDoc = factory.newDocumentBuilder().newDocument();
	    		    	
	    	// create SOAP envelope
	    	String envelopeName = SOAPConstants.SOAP_PRE + ":" + SOAPConstants.SOAP_ENV;
	    	Element envelope = xmlDoc.createElementNS(SOAPConstants.SOAP_NS, envelopeName);
	    	
	    	xmlDoc.appendChild(envelope);

	    	// create SOAP header
	    	String headerName = SOAPConstants.SOAP_PRE + ":" + SOAPConstants.SOAP_HEADER;
	    	header = xmlDoc.createElementNS(SOAPConstants.SOAP_NS, headerName);
	    	
	    	envelope.appendChild(header);
	    	
	    	// create SOAP body
	    	String bodyName = SOAPConstants.SOAP_PRE + ":" + SOAPConstants.SOAP_BODY;
	    	body = xmlDoc.createElementNS(SOAPConstants.SOAP_NS, bodyName);
	    	
	    	body.setAttribute("id", bodyId);
	    	
	    	envelope.appendChild(body);
	    	
	    } catch (ParserConfigurationException e) {
			e.printStackTrace();
		}
	    
	}

	public SOAPMessage(String xml) {
		
		InputStream is = getISFromXML(xml);
		if (is != null) setSOAPMessageFromIS(is);

	}
	
	public SOAPMessage(InputStream is) {
		setSOAPMessageFromIS(is);
	}
	
	public SOAPMessage(Document xmlDoc) {

		this.xmlDoc = xmlDoc;

		this.header = getSOAPElement(xmlDoc, SOAPConstants.SOAP_HEADER);		    
		this.body   = getSOAPElement(xmlDoc, SOAPConstants.SOAP_BODY);

	}
    
	private void setSOAPMessageFromIS(InputStream is) {

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);

		try {
	    
			this.xmlDoc = factory.newDocumentBuilder().parse(is);
	    
			this.header = getSOAPElement(xmlDoc, SOAPConstants.SOAP_HEADER);		    
			this.body   = getSOAPElement(xmlDoc, SOAPConstants.SOAP_BODY);
	    
	   } catch (Exception e) {
		   e.printStackTrace();
	    
	   } finally {
		   try {
			   is.close();
			   
		   } catch (IOException e) {
			   e.printStackTrace();
		   }
	   }
		
	}
	
	private Element getSOAPElement(Document xmlDoc, String localName) {

	    NodeList nodes = xmlDoc.getElementsByTagNameNS(SOAPConstants.SOAP_NS, localName);
	    if (nodes.getLength() == 0) return null;

        return (Element) nodes.item(0);

    }
	
	public Document getXMLDoc() {
		return this.xmlDoc;
	}
	
	// this method adds content to the SOAP body element
	
	public void setContent(Node content) throws Exception {
		
		if (this.body == null) throw new Exception("Invalid SOAP Message detected (missing body).");
		this.body.appendChild(content);
		
	}
	
	public Node getContent() throws Exception {

		if (this.body == null) throw new Exception("Invalid SOAP Message detected (missing body).");
		return this.body.getFirstChild();

	}
	
	// this method supports the signing of the SOAP message
	
	public void sign() throws Exception {
		
		if (this.credentialInfo == null) throw new Exception("No credentials for signing provided.");
		
		SecSignature signature = new SecSignature(this.credentialInfo);
		this.xmlDoc = signature.sign(this.xmlDoc);
		
	}
	
	// this method verifies the signature assigned with th SOAP message
	
	public void verify() {
		
		SecValidator validator = new SecValidator();
		validator.verify(this.xmlDoc);
		
	}
	
	public String toXML() {
		return XMLSerializer.serialize(this.xmlDoc);
	}

	private InputStream getISFromXML(String xml) {
		
		byte[] bytes;
		try {

			bytes = xml.getBytes("UTF-8");
			return new ByteArrayInputStream(bytes);
		
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		
		return null;
		
	}
	
}
