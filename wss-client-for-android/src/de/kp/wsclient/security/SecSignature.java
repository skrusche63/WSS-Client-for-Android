package de.kp.wsclient.security;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.InclusiveNamespaces;
import org.apache.xml.security.utils.Base64;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

public class SecSignature extends SecBase {

	private X509Certificate certificate;
	private PrivateKey privateKey;
	
	private Element wsseSecurity;
	
	static {
    	// initialize apache santuario framework
    	org.apache.xml.security.Init.init();
    }

	public SecSignature(SecCredentialInfo credentialInfo) {
		
		this.certificate = credentialInfo.getCertificate();
		this.privateKey = credentialInfo.getPrivateKey();
		
	}
	
	public void setCertificate(X509Certificate certificate) {
		this.certificate = certificate;
	}
	
	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}
	
	// this method adds a signed wsse:Security element to
	// a SOAP envelop document
	
	public Document sign(Document xmlDoc) throws Exception {
		
		// acquire SOAP header element
		Element soapHeader = getSOAPHeader(xmlDoc);
		if (soapHeader == null) throw new Exception("SOAP Header not found.");

		// this method determines whether there is already
		// a wsse:Security element present due to former
		// encryption processing
		
		boolean hasSecHeader = isSecHeader(xmlDoc);
		
		// add wsse:Security element to SOAP Header
		this.wsseSecurity = createWSSESecurity(xmlDoc);
		if (hasSecHeader == false) soapHeader.appendChild(wsseSecurity);
		
		return xmlDoc;

	}
	
	private Element createWSSESecurity(Document xmlDoc) throws Exception {
		
		this.wsseSecurity = getSecHeader(xmlDoc);
		
		// add wsse:BinarySecurityToken
		Element wsseBinarySecurityToken = createWSSEBinarySecurityToken(xmlDoc);
		wsseSecurity.appendChild(wsseBinarySecurityToken);
		
		XMLSignature signature = createSignature(xmlDoc);
		
        // finally sign the referenced body and add the signature value
        // to the respective signature
        
   	 	// <ds:SignatureValue>PipXJ2Sfc+LTDnq4pM5JcIYt9gg=</ds:SignatureValue>

		// add ds:Signature to the security header
		wsseSecurity.appendChild(signature.getElement());
        
        if (this.privateKey != null) signature.sign(this.privateKey);
		return wsseSecurity;
		
	}
	
	/*
	 * <wsse:BinarySecurityToken 
	 *	 EncodingType="http://docs.oasisopen.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" 
	 * 		ValueType="http://docs.oasisopen.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
	 *	 wsu:Id="urn:oasis:names:tc:ebxml-regrep:rs:security:SenderCert"> ...(cert)...
	 * </wsse:BinarySecurityToken>
	 */

	private Element createWSSEBinarySecurityToken(Document xmlDoc) throws Exception {

		String qualifiedName = SecConstants.WSSE_PRE + ":" + SecConstants.BINARY_TOKEN_LN;
		Element wsseBinarySecurityToken = xmlDoc.createElementNS(SecConstants.WSSE_NS, qualifiedName);
		
		// attribute:: EncodingType
		wsseBinarySecurityToken.setAttribute("EncodingType", SecConstants.BST_BASE64_ENCODING);
		
		// attribute:: ValueType
		wsseBinarySecurityToken.setAttribute("ValueType", SecConstants.BST_VALUE_TYPE);
		
		// wsu:Id
		wsseBinarySecurityToken.setAttributeNS(SecConstants.WSU_NS, SecConstants.WSU_PRE + ":Id", SecConstants.SENDER_CERT);
		
		// add certificate
		wsseBinarySecurityToken.appendChild(createToken(xmlDoc));
		return wsseBinarySecurityToken;

	}

	/*
	 * <ds:Signature>
	 * 	<ds:SignedInfo>
	 *		<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#&quot; ">
	 *			<c14n:InclusiveNamespaces PrefixList="wsse soap" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#"/>
	 *		</ds:CanonicalizationMethod>
	 *		<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
	 *		<ds:Reference URI="#TheBody">
	 * 			<ds:Transforms>
	 *				<ds:Transform Algorithm="http://www.w3.org/2001/10/xmlexc-c14n#">
	 *					<c14n:InclusiveNamespaces PrefixList="" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#"/>
	 *				</ds:Transform>
	 *			</ds:Transforms>
	 *			<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
	 *			<ds:DigestValue>i3qi5GjhHnfoBn/jOjQp2mq0Na4=</ds:DigestValue>
	 *		</ds:Reference>
	 *	</ds:SignedInfo>
	 *	<ds:SignatureValue>PipXJ2Sfc+LTDnq4pM5JcIYt9gg=</ds:SignatureValue>
	 *	<ds:KeyInfo>
	 *		<wsse:SecurityTokenReference>
	 *			<wsse:Reference URI="#urn:oasis:names:tc:ebxmlregrep:rs:security:SenderCert" ValueType="http://docs.oasisopen.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/>
	 * 		</wsse:SecurityTokenReference>
	 *	</ds:KeyInfo>
	 * </ds:Signature>
	 * 
	 */
	private XMLSignature createSignature(Document xmlDoc) throws Exception {

		 //	<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
		 //		<c14n:InclusiveNamespaces PrefixList="wsse soap" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#"/>
		 //	</ds:CanonicalizationMethod>

		String canonAlgo = SecConstants.C14N_EXCL_OMIT_COMMENTS;

       	Element canonElem = XMLUtils.createElementInSignatureSpace(xmlDoc, Constants._TAG_CANONICALIZATIONMETHOD);
        canonElem.setAttributeNS(null, Constants._ATT_ALGORITHM, canonAlgo);
        
        // inclusive namespaces
        List<String> prefixes = getInclusivePrefixes(this.wsseSecurity, false);

        InclusiveNamespaces inclusiveNamespaces = new InclusiveNamespaces(xmlDoc, new HashSet<String>(prefixes));
        canonElem.appendChild(inclusiveNamespaces.getElement());
		
		// determine signing algorithm
        // <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
		
        String sigAlgo = getSignatureAlgorithm();
		if (sigAlgo == null) throw new Exception("[Signature] Unknown signature algorithm.");

		// create signature
		SignatureAlgorithm signatureAlgorithm = new SignatureAlgorithm(xmlDoc, sigAlgo);
        XMLSignature sig = new XMLSignature(xmlDoc, null, signatureAlgorithm.getElement(), canonElem);
        
        /*
         *	<ds:KeyInfo>
         *		<wsse:SecurityTokenReference>
         *			<wsse:Reference URI="#urn:oasis:names:tc:ebxmlregrep:rs:security:SenderCert" ValueType="http://docs.oasisopen.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/>
         * 		</wsse:SecurityTokenReference>
         *	</ds:KeyInfo>
         */

        KeyInfo keyInfo = sig.getKeyInfo();
        keyInfo.getElement().appendChild(createSTR(xmlDoc));
      
   	 	/*	
   	 	 * <ds:Reference URI="#TheBody">
   	 	 * 		<ds:Transforms>
   	 	 *			<ds:Transform Algorithm="http://www.w3.org/2001/10/xmlexc-c14n#">
   	 	 *				<c14n:InclusiveNamespaces PrefixList="" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#"/>
   	 	 *			</ds:Transform>
   	 	 *		</ds:Transforms>
   	 	 *		<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
   	 	 *		<ds:DigestValue>i3qi5GjhHnfoBn/jOjQp2mq0Na4=</ds:DigestValue>
   	 	 *	</ds:Reference>
		 */

  	 	 // <ds:Transforms>
  	 	 //		<ds:Transform Algorithm="http://www.w3.org/2001/10/xmlexc-c14n#">
  	 	 //			<c14n:InclusiveNamespaces PrefixList="" xmlns:c14n="http://www.w3.org/2001/10/xml-exc-c14n#"/>
  	 	 //		</ds:Transform>
  	 	 //	</ds:Transforms>

        Transforms transforms = new Transforms(xmlDoc);
        transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
        
        transforms.item(0).getElement().appendChild(inclusiveNamespaces.getElement());
        
        Element body = getSOAPBody(xmlDoc);
        String referenceURI = "#" + body.getAttribute("id");
        
        // the digest method used with the subsequent call is
        // <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        sig.addDocument(referenceURI, transforms);
 
        return sig;

	}
	
	// determine signature algorithm from public key algorithm
	
	private String getSignatureAlgorithm() {

		if (this.certificate == null) return null;
		
		// determine signing algorithm
		String sigAlgo = null;

    	String pubKeyAlgo = this.certificate.getPublicKey().getAlgorithm();
        if (pubKeyAlgo.equalsIgnoreCase("DSA")) {
            sigAlgo = XMLSignature.ALGO_ID_SIGNATURE_DSA;

        } else if (pubKeyAlgo.equalsIgnoreCase("RSA")) {
            sigAlgo = XMLSignature.ALGO_ID_SIGNATURE_RSA;
        }
 		
		return sigAlgo;

	}

    private Text createToken(Document xmlDoc) throws Exception {
        
    	if (this.certificate == null) throw new Exception("[Binary Security Token] Illegal certificate.");
    	byte[] data = certificate.getEncoded();
    	
    	return xmlDoc.createTextNode((Base64.encode(data)));
 
    }
    
    // get the List of inclusive prefixes from the DOM Element argument; 
    // adapted from WSS4J

    // TODO FAILURE: return list is null
    private List<String> getInclusivePrefixes(Element target, boolean excludeVisible) {
       
    	List<String> result = new ArrayList<String>();
        Node parent = target;
        
        while (parent.getParentNode() != null && !(Node.DOCUMENT_NODE == parent.getParentNode().getNodeType())) {

        	parent = parent.getParentNode();
            NamedNodeMap attributes = parent.getAttributes();
            
            for (int i = 0; i < attributes.getLength(); i++) {
                Node attribute = attributes.item(i);
                
                if (SecConstants.XMLNS_NS.equals(attribute.getNamespaceURI())) {
 
                	if ("xmlns".equals(attribute.getNodeName())) {
                        result.add("#default");
                    } else {
                        result.add(attribute.getLocalName());
                    }
                }
            }
        }

        if (excludeVisible == true) {
 
        	NamedNodeMap attributes = target.getAttributes();
            for (int i = 0; i < attributes.getLength(); i++) {
                Node attribute = attributes.item(i);
                if (SecConstants.XMLNS_NS.equals(attribute.getNamespaceURI())) {
                    if ("xmlns".equals(attribute.getNodeName())) {
                        result.remove("#default");
                    } else {
                        result.remove(attribute.getLocalName());
                    }
                }
                if (attribute.getPrefix() != null) {
                    result.remove(attribute.getPrefix());
                }
            }

            if (target.getPrefix() == null) {
                result.remove("#default");
            } else {
                result.remove(target.getPrefix());
            }
        }

        return result;
    }

}
