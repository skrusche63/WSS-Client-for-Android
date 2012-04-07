package de.kp.wsclient.security;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

public class SecDecryptor extends SecBase {

	private Document xmlDoc;
	private List<WSDataRef> dataRefs;
	
	static {
    	// initialize apache santuario framework
    	org.apache.xml.security.Init.init();
    }

	public SecDecryptor() {
		
	}
	
	// decryption is processed after the signature of 
	// a SOAP message has been verified
	
	public Document decrypt(Document xmlDoc) throws Exception {
		
		this.xmlDoc = xmlDoc;

		// determine security header from envelope document
		Element elem = getSecHeader(this.xmlDoc);

	    /*
	     * EXAMPLE STRUCTURE
	     *
	     * <wsse:Security>
	     * 	<xenc:EncryptedKey>
	     * 		<xenc:EncryptionMethod Algorithm="�"/>
	     * 		<ds:KeyInfo>
	     * 			<wsse:SecurityTokenReference>
	     * 
	     */

		// determine EncryptedKey
		Element encKey = null;
		
		NodeList children = elem.getChildNodes();		
		for (int i=0; i < children.getLength(); i++) {
			
			Node child = children.item(i);
			
			String ns = child.getNamespaceURI();
			String ln = child.getLocalName();

			if (ln.equals("EncryptedKey") && ns.equals(SecConstants.ENC_NS)) {

				encKey = (Element)child;
				break;
			
			}
			
		}

		if (encKey == null) return null;
				
        // lookup xenc:EncryptionMethod, get the Algorithm attribute to determine
        // how the key was encrypted. Then check if we support the algorithm

		String encAlgo = getEncAlgo(encKey);
        if (encAlgo == null) {
            throw new Exception("[SecDecryptor] Unsupported algorithm.");
        }

        Cipher cipher = SecUtil.getCipherInstance(encAlgo);

        // Now lookup CipherValue.
        Element tmp = SecUtil.getDirectChildElement(elem, "CipherData", SecConstants.ENC_NS);
        Element xencCipherValue = null;

        if (tmp != null) {
            xencCipherValue = SecUtil.getDirectChildElement(tmp, "CipherValue", SecConstants.ENC_NS);
        }
        
        if (xencCipherValue == null) {
            throw new Exception("[SecDecryptor] Invalid security.");
        }
	            
        List<String> dataRefURIs = getDataRefURIs(elem);
	            
        byte[] encryptedEphemeralKey = null;
        byte[] decryptedBytes = null;
	            
        try {
            encryptedEphemeralKey = getDecodedBase64EncodedData(xencCipherValue);
            decryptedBytes = cipher.doFinal(encryptedEphemeralKey);

        } catch (IllegalStateException ex) {
            throw new Exception("[SecDecrytor] Check failed.");

        }

        dataRefs = decryptDataRefs(dataRefURIs, decryptedBytes);
		return this.xmlDoc;
		
	}

	public Element getDecryptedElement() {
		
		if ((this.dataRefs == null) || (this.dataRefs.size() == 0)) return null;
		WSDataRef dataRef = this.dataRefs.get(0);
		
		return dataRef.getProtectedElement();
		
	}
	
    // Decrypt all data references

	private List<WSDataRef> decryptDataRefs(List<String> dataRefURIs, byte[] decryptedBytes) throws Exception {

        // At this point we have the decrypted session (symmetric) key. According
        // to W3C XML-Enc this key is used to decrypt _any_ references contained in
        // the reference list
        if (dataRefURIs == null || dataRefURIs.isEmpty()) {
            return null;
        }
        
        List<WSDataRef> dataRefs = new ArrayList<WSDataRef>();
        for (String dataRefURI:dataRefURIs) {
 
        	WSDataRef dataRef = decryptDataRef(dataRefURI, decryptedBytes);
            dataRefs.add(dataRef);
        
        }
        return dataRefs;
    
	}

    // Decrypt an EncryptedData element referenced by dataRefURI

	private WSDataRef decryptDataRef(String dataRefURI, byte[] decryptedData) throws Exception {
 
        // Find the encrypted data element referenced by dataRefURI
        Element encryptedDataElement = findEncryptedDataElement(dataRefURI);

        // Prepare the SecretKey object to decrypt EncryptedData
        String symEncAlgo = getEncAlgo(encryptedDataElement);
        SecretKey symmetricKey = null;
        
        try {
            symmetricKey = SecUtil.prepareSecretKey(symEncAlgo, decryptedData);
        
        } catch (IllegalArgumentException ex) {
            throw new Exception("[SecDecryptor] Unsupported algorithm.");

        }

        return decryptEncryptedData(dataRefURI, encryptedDataElement, symmetricKey, symEncAlgo);

	}

    /*
     * Look up the encrypted data. First try Id="someURI". If no such Id then try 
     * wsu:Id="someURI".
     */

	private Element findEncryptedDataElement(String dataRefURI) throws Exception {
		
        DOMCallbackLookup callbackLookup = new DOMCallbackLookup(this.xmlDoc);

        Element encryptedDataElement = callbackLookup.getElement(dataRefURI, null, true);
        if (encryptedDataElement == null) {
            throw new Exception("[SecDecryptor] Invalid security.");
        }
        
        if (encryptedDataElement.getLocalName().equals(SecConstants.ENCRYPTED_HEADER) && encryptedDataElement.getNamespaceURI().equals(SecConstants.WSSE11_NS)) {

        	Node child = encryptedDataElement.getFirstChild();
            while (child != null && child.getNodeType() != Node.ELEMENT_NODE) {
                child = child.getNextSibling();
            }
            
            return (Element)child;
        
        }
        
        return encryptedDataElement;
    
	}
	
    // Decrypt the EncryptedData argument using a SecretKey.

	public WSDataRef decryptEncryptedData(String dataRefURI, Element encData, SecretKey symmetricKey, String symEncAlgo) throws Exception {

		XMLCipher xmlCipher = null;
        try {
            
        	xmlCipher = XMLCipher.getInstance(symEncAlgo);
 
            xmlCipher.setSecureValidation(true);
            xmlCipher.init(XMLCipher.DECRYPT_MODE, symmetricKey);
        
        } catch (XMLEncryptionException ex) {
            throw new Exception("[SecDecryptor] Unsupported algorithm.");
            
        }

        WSDataRef dataRef = new WSDataRef();

        dataRef.setWsuId(dataRefURI);
        dataRef.setAlgorithm(symEncAlgo);
        
        boolean content = SecUtil.isContent(encData);
        dataRef.setContent(content);
        
        Node parent = encData.getParentNode();
        Node previousSibling = encData.getPreviousSibling();
        if (content) {
            encData = (Element) encData.getParentNode();
            parent = encData.getParentNode();
        }
        
        try {
            xmlCipher.doFinal(this.xmlDoc, encData, content);
            
        } catch (Exception ex) {
            throw new Exception("[SecDecryptor] Check failed.");
        
        }
        
        if (parent.getLocalName().equals(SecConstants.ENCRYPTED_HEADER) && parent.getNamespaceURI().equals(SecConstants.WSSE11_NS)) {
                
            Node decryptedHeader = parent.getFirstChild();
            Node soapHeader = parent.getParentNode();
            soapHeader.replaceChild(decryptedHeader, parent);

            dataRef.setProtectedElement((Element)decryptedHeader);
            dataRef.setXpath(getXPath(decryptedHeader));

        } else if (content) {
            dataRef.setProtectedElement(encData);
            dataRef.setXpath(getXPath(encData));
        
        } else {
        
        	Node decryptedNode;
            if (previousSibling == null) {
                decryptedNode = parent.getFirstChild();
            
            } else {
                decryptedNode = previousSibling.getNextSibling();
            }
            
            if (decryptedNode != null && Node.ELEMENT_NODE == decryptedNode.getNodeType()) {
                dataRef.setProtectedElement((Element)decryptedNode);
            }
            
            dataRef.setXpath(getXPath(decryptedNode));
        }
        
        return dataRef;
    }

	private String getEncAlgo(Node encKey) throws Exception {
    
		Element tmp = SecUtil.getDirectChildElement(encKey, "EncryptionMethod", SecConstants.ENC_NS);
    
		String symEncAlgo = null;
		if (tmp != null) {
			symEncAlgo = tmp.getAttribute("Algorithm");
			if (symEncAlgo == null || "".equals(symEncAlgo)) {
				throw new Exception("[SecDecryptor] Unsupported algorithm.");
			}
		}
		return symEncAlgo;
	}

    // Find the list of all URIs that this encrypted Key references

	private List<String> getDataRefURIs(Element xencEncryptedKey) {

		// Lookup the references that are encrypted with this key
        Element refList = SecUtil.getDirectChildElement(xencEncryptedKey, "ReferenceList", SecConstants.ENC_NS);
        List<String> dataRefURIs = new LinkedList<String>();

        if (refList != null) {
        
        	for (Node node = refList.getFirstChild(); node != null; node = node.getNextSibling()) {
                
        		if (Node.ELEMENT_NODE == node.getNodeType() && SecConstants.ENC_NS.equals(node.getNamespaceURI()) && "DataReference".equals(node.getLocalName())) {
                    
        			String dataRefURI = ((Element) node).getAttribute("URI");                   
                    if (dataRefURI.charAt(0) == '#') {
                        dataRefURI = dataRefURI.substring(1);
                    }
 
                    dataRefURIs.add(dataRefURI);
                }
            }
        }
        
        return dataRefURIs;
    
	}

    private static byte[] getDecodedBase64EncodedData(Element element) throws Exception {
        
    	StringBuilder sb = new StringBuilder();
        Node node = element.getFirstChild();
        
        while (node != null) {
            if (Node.TEXT_NODE == node.getNodeType()) {
                sb.append(((Text) node).getData());
            }
            node = node.getNextSibling();
        }
        
        String encodedData = sb.toString();
        return org.apache.xml.security.utils.Base64.decode(encodedData);
    
    }
    
    public String getXPath(Node decryptedNode) {

    	if (decryptedNode == null) {
            return null;
        }
        
        String result = "";
        if (Node.ELEMENT_NODE == decryptedNode.getNodeType()) {
        
        	result = decryptedNode.getNodeName();
            result = prependFullPath(result, decryptedNode.getParentNode());
        
        } else if (Node.ATTRIBUTE_NODE == decryptedNode.getNodeType()) {
            
        	result = "@" + decryptedNode.getNodeName();
            result = prependFullPath(result, ((Attr)decryptedNode).getOwnerElement());
        
        } else {
            return null;
        }
        
        return result;
    }

    // Recursively build an absolute xpath (starting with the root)

    private String prependFullPath(String xpath, Node node) {

    	if (node == null) {
            // probably a detached node... not really useful
            return null;
        
    	} else if (Node.ELEMENT_NODE == node.getNodeType()) {
            xpath = node.getNodeName() + "/" + xpath;
            return prependFullPath(xpath, node.getParentNode());
        
    	} else if (Node.DOCUMENT_NODE == node.getNodeType()) {
            return "/" + xpath;
        
    	} else {
            return prependFullPath(xpath, node.getParentNode());
        }
    }

}
