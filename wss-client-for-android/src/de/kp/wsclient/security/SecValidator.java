package de.kp.wsclient.security;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.Base64;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/* 
 * This class verifies a WS-Security signature. It is a modified version
 * of the respective method from wss4j 'SignatureProcessor'
 * 
 * The function checks the ds:KeyInfo for a wsse:SecurityTokenReference element. 
 * If yes, the next is to get the certificate. This is done by evaluating the
 * URI reference to a binary security token contained in the wsse:Security header.  
 * 
 * If the dereferenced token is a binary security token, the contained certificate 
 * is extracted.
 * 
 * The method then checks if the certificate is valid; to this end the function
 * org.apache.xml.security.signature.XMLSignature#checkSignatureValue(X509Certificate) 
 * is invoked.
 */

public class SecValidator {
	
    static {
    	// initialize apache santuario framework
    	org.apache.xml.security.Init.init();
    }

    public SecValidator() {	
    }
	
    public void verify(Document xmlDoc) {
	
		boolean valid = false;
	
		try {
	
		    // acquire signature element
		    Element sigElement = getSignature(xmlDoc);
		    if (sigElement == null) throw new Exception("<ds:Signature> Element is missing.");
	
		    // create signature element		    
		    XMLSignature signature = new XMLSignature(sigElement, null);
	
		    // acquire KeyInfo
	        
	        // the ds:KeyInfo element does not contain values directly, but 
		    // refers to the binary security token
		   
		    KeyInfo keyInfo = signature.getKeyInfo();
		    if (keyInfo == null) throw new Exception("<ds:KeyInfo> Element is corrupted.");

			 // acquire security token reference

	        Node secTokenRef = getChildNode(keyInfo.getElement(), SecConstants.SECURITY_TOKEN_REFERENCE, SecConstants.WSSE_NS);
	        if (secTokenRef == null) throw new Exception("Security Token Reference not found.");

	        // get reference element (= first element of security token reference)
	        
	        Element refElement = getFirstElement((Element)secTokenRef);
	        if (refElement == null) throw new Exception("Invalid security reference.");

	        SecReference ref = new SecReference(refElement);
	        String refURI  = ref.getURI();

	        if (refURI == null) throw new Exception("Invalid reference URI.");

	        // the reference should refer to the binary security token of the request issuer
	        String refID = (refURI.charAt(0) == '#') ? refURI.substring(1) : null;

	        // we enforce a binary security token
	        Element bsToken = getBSToken(xmlDoc, refID);
	        if (bsToken == null) throw new Exception("No Binary Security Token");

	        // determine certificate from binary security token	        
	        X509Certificate cert = getX509Certificate(bsToken); 
	    
		    //------------------ check signature value ----------------------
		    
		    // the signature is either checked from the public key provided
		    // or the X509 certificate that comes with the SOAP message
		    
		    if (cert == null) {
	
		    	PublicKey pk = signature.getKeyInfo().getPublicKey();
		    	if (pk == null) {
		    		throw new Exception("Did not find Certificate or Public Key");
		    	}
		    	valid = signature.checkSignatureValue(pk);
		    
		    } else {
		    	valid = signature.checkSignatureValue(cert);
		    }
		
		    if (valid == false) throw new Exception("Invalid signature found.");
		    
		} catch (Exception e) {
		    e.printStackTrace();
		}
   
	}

    private Element getSignature(Document xmlDoc) throws Exception {

	    NodeList nodes = xmlDoc.getElementsByTagNameNS(Constants.SignatureSpecNS, SecConstants.SIGNATURE);
	    if (nodes.getLength() == 0) return null;

        return (Element) nodes.item(0);

    }

    private Element getBSToken(Document xmlDoc, String tokenID) {

	    NodeList nodes = xmlDoc.getElementsByTagNameNS(SecConstants.WSSE_NS, SecConstants.BINARY_TOKEN_LN);
	    if (nodes.getLength() == 0) return null;

		Element element = (Element) nodes.item(0);		
        if (element.hasAttributeNS(SecConstants.WSU_NS, "Id") && tokenID.equals(element.getAttributeNS(SecConstants.WSU_NS, "Id")))
        	return element;
		
		return null;
		
	}

	// this method retrieves the X.509 certificate from the <wsse:BinarySecurityToken>
	
	private X509Certificate getX509Certificate(Element element) throws Exception {

		String encodedData = element.getFirstChild().getNodeValue();
		byte[] decodedData;
		
		try {
			decodedData = Base64.decode(encodedData);

		} catch (Exception e) {
			throw new Exception("X.509 Certificate Decoding Error.");
		
		}

        X509Certificate cert = null;
        InputStream is = null;

        try {

        	CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

            is = new ByteArrayInputStream(decodedData);
        	cert = (X509Certificate)certificateFactory.generateCertificate(is);

        } catch (CertificateException e) {
        	e.printStackTrace();

        } finally {
        	if (is != null) {
        		try {
        			is.close();
        		} catch (Exception e) {
        		}
        	}
        }

        return cert;
        
	}

    /************************************************************************
     * 
     * DOM UTILS     DOM UTILS     DOM UTILS     DOM UTILS     DOM UTILS
     * 
     ***********************************************************************/
	
	// this is a helper method to retrieve the first element of a parent element

	private Element getFirstElement(Element parentElement) {

		for (Node childNode = parentElement.getFirstChild(); childNode != null; childNode = childNode.getNextSibling()) {
            if (childNode instanceof Element) {
                return (Element) childNode;
            }
        }
        return null;

	}
    
    // this is a helper method to determine a certain child node directly
 	// from refering to the local name and its namespace

 	private Node getChildNode(Node parentNode, String localName, String namespace) {

     	for (Node childNode = parentNode.getFirstChild(); childNode != null; childNode = childNode.getNextSibling()) {
             if (localName.equals(childNode.getLocalName()) && namespace.equals(childNode.getNamespaceURI())) {
 	            return childNode;
             }
         }

     	return null;
     }
}