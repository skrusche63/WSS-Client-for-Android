package de.kp.wsclient.security;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * This is the base class for SecEncryptor, SecDecryptor
 * and also SecSignature and holds common methods to
 * create or retrieve SOAP message elements.
 * 
 * @author Stefan Krusche (krusche@dr-kruscheundpartner.de)
 *
 */
public class SecBase {

    /**
     * This method creates a Security Token Reference (STR) element,
     * which holds a Reference element with a predefined URI, that
     * points to the Binary Security Token (BST) as part of the 
     * wsse:Security header.
     * 
     * @param xmlDoc
     * @return
     */
    protected Element createSTR(Document xmlDoc) {
        
    	String qualifiedName = SecConstants.WSSE_PRE + ":" + SecConstants.SECURITY_TOKEN_REFERENCE;
    	Element secRef = xmlDoc.createElementNS(SecConstants.WSSE_NS, qualifiedName);
 
    	Element ref = createReference(xmlDoc);
    	
    	ref.setAttribute("URI", "#" + SecConstants.SENDER_CERT);
    	ref.setAttribute("ValueType",  SecConstants.X509TOKEN_NS + "#X509v3");
 
    	secRef.appendChild(ref);
    	return secRef;
    	
    }
   
    /**
     * This method creates Reference element.
     * 
     * @param xmlDoc
     * @return
     */
    protected Element createReference(Document xmlDoc) {

    	String qualifiedName = SecConstants.WSSE_PRE + ":" + SecConstants.REFERENCE;
    	Element ref = xmlDoc.createElementNS(SecConstants.WSSE_NS, qualifiedName);
    	
    	return ref;
    	
    }

    /**
     * This method determines whether there is a wsse:Security element in
     * a W3C DOM document or not.
     * 
     * @param xmlDoc
     * @return
     */
    protected boolean isSecHeader(Document xmlDoc) {
    	NodeList nodes = xmlDoc.getElementsByTagNameNS(SecConstants.WSSE_NS, SecConstants.SECURITY);
	    return (nodes.getLength() == 0) ? false : true;
    }
    
    protected Element getSecHeader(Document xmlDoc) throws Exception {

	    NodeList nodes = xmlDoc.getElementsByTagNameNS(SecConstants.WSSE_NS, SecConstants.SECURITY);
	    if (nodes.getLength() == 0) return createSecHeader(xmlDoc);

        return (Element) nodes.item(0);

    }
    
	/**
	 * This method creates a wsse:Security element.
	 * 
	 * @param xmlDoc
	 * @return
	 * @throws Exception
	 */
	protected Element createSecHeader(Document xmlDoc) throws Exception {
		
		String qualifiedName = SecConstants.WSSE_PRE + ":" + SecConstants.SECURITY;
		return xmlDoc.createElementNS(SecConstants.WSSE_NS, qualifiedName);
		
	}
	
    /**
     * This method retrieves a soap:Header element from a 
     * W3C DOM document.
     * 
     * @param xmlDoc
     * @return
     */
    protected Element getSOAPHeader(Document xmlDoc) {

	    NodeList nodes = xmlDoc.getElementsByTagNameNS(SecConstants.URI_SOAP12_ENV, SecConstants.ELEM_HEADER);
	    if (nodes.getLength() == 0) return null;

        return (Element) nodes.item(0);

    }

    /**
     * This method retrieves a soap:Body element from a
     * W3C DOM document.
     * 
     * @param xmlDoc
     * @return
     */
    protected Element getSOAPBody(Document xmlDoc) {

	    NodeList nodes = xmlDoc.getElementsByTagNameNS(SecConstants.URI_SOAP12_ENV, SecConstants.ELEM_BODY);
	    if (nodes.getLength() == 0) return null;

        return (Element) nodes.item(0);

    }

}
