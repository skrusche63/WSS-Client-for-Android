package de.kp.wsclient.security;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.keys.KeyInfo;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import de.kp.wsclient.util.UUIDGenerator;

/*
 * This class MUST always be used in conjunction with SecSignature, as
 * e.g. no BinarySecurityToken element is created (done through signing)
 * 
 * 
 * This class implements OASIS Web Services Security X.509 Certificate
 * Token Profile 1.1 and is restricted to referencing a Binaray Security
 * Token, i.e. no subject key identifier or a reference to an issuer and
 * serial number is supported.
 * 
 */


public class SecEncryptor extends SecBase {

	static {
    	// initialize apache santuario framework
    	org.apache.xml.security.Init.init();
    }

	// User credentials
	private X509Certificate certificate;

    // Session key used as the secret in key derivation
    private byte[] ephemeralKey;
    
    // Symmetric key used in the EncryptedKey.
    private SecretKey symmetricKey = null;

    // Encrypted bytes of the ephemeral key
    private byte[] encryptedEphemeralKey;

    // Algorithm used to encrypt the ephemeral key
    private String keyEncAlgo = SecConstants.KEYTRANSPORT_RSA15;
    
    // Algorithm to be used with the ephemeral key
    private String symEncAlgo = SecConstants.AES_128;

    // xenc:EncryptedKey element
    private Element encryptedKeyElement = null;

    // Indicates whether to encrypt the symmetric key into an EncryptedKey or not.
    private boolean encryptSymmKey = true;

    // The Token identifier of the token that the DerivedKeyToken is (or to be) derived from.
    private String encKeyId = null;

    private KeyInfo keyInfo;
    private Document xmlDoc;
    
	/*
	 * This class encrypts a WS-Security envelope; note, that
	 * encryption MUST be done before signing the envelope is
	 * invoked.
	 */
	
	public SecEncryptor(SecCredentialInfo credentialInfo) {		
		this.certificate = credentialInfo.getCertificate();
	}
	
	public void setCertificate(X509Certificate certificate) {
		this.certificate = certificate;
	}

    /*
     * builds the SOAP envelope with encrypted Body and adds encrypted 
     * key; this method is an adapted version of the WSS4j build method
     */

	public Document encrypt(Document xmlDoc) throws Exception {
		
		// set reference to xml document as this is used
		// with other encryption methods
		
		this.xmlDoc = xmlDoc;		
        prepare();
	        
        Element envelope = xmlDoc.getDocumentElement();
        List<SecEncPart> parts = new ArrayList<SecEncPart>();

        String soapNamespace = SecUtil.getSOAPNamespace(envelope);
            
        SecEncPart encP = new SecEncPart(SecConstants.ELEM_BODY, soapNamespace, "Content");
        parts.add(encP);
        
        Element refs = encryptForRef(parts);
        if (this.encryptedKeyElement != null) {

            /*
             * Adds the internal Reference element to this Encrypt data.
             
             * The reference element must be created by the encryptForInternalRef
             * method. The reference element is added to the EncryptedKey element 
             * of this encrypt block.
             */
        	this.encryptedKeyElement.appendChild(refs);
        	
            /*
             * Prepend the EncryptedKey element to the elements already in the 
             * Security header.
             * 
             * The method allows to insert the EncryptedKey element at any position 
             * in the Security header.
             */
        	Element secHeader = getSecHeader(this.xmlDoc);
            SecUtil.prependChildElement(secHeader, encryptedKeyElement);
        
        } else {
            /*
             * Adds (prepends) the external Reference element to the Security header.
             * 
             * The reference element must be created by the encryptForExternalRef
             *  method. The method prepends the reference element in the SecurityHeader.
             */
        	Element secHeader = getSecHeader(this.xmlDoc);
        	SecUtil.prependChildElement(secHeader, refs);
        
        }

        return xmlDoc;
        
    }

	private void prepare() throws Exception {
	
		// the subsequent part of code is adapted from the 'prepare'
		// method of WSS4J (1.6.4) WSSecEncrypt
	    /*
	     * If no external key (symmetricalKey) was set generate an encryption
	     * key (session key) for this Encrypt element. This key will be
	     * encrypted using the public key of the receiver
	     */
	    if (this.ephemeralKey == null) {
	        
	    	if (this.symmetricKey == null) {           
	    		KeyGenerator keyGen = getKeyGenerator();
	            this.symmetricKey = keyGen.generateKey();            
	    	} 
	        
	    	this.ephemeralKey = this.symmetricKey.getEncoded();
	    
	    }
	    
	    if (this.symmetricKey == null) this.symmetricKey = prepareSecretKey(this.symEncAlgo, this.ephemeralKey);
	    
	    /*
	     * Get the certificate that contains the public key for the public key
	     * algorithm that will encrypt the generated symmetric (session) key.
	     */
	    
	    if (this.encryptSymmKey) {
	        prepareInternal(this.symmetricKey, this.certificate);
	
	    } else {
	        this.encryptedEphemeralKey = this.ephemeralKey;
	
	    }

	}

	/*
	 * Encrypt the symmetric key data and prepare the EncryptedKey element
	 * This method does the most work for to prepare the EncryptedKey element.
	 */

	private void prepareInternal(SecretKey secretKey, X509Certificate remoteCert) throws Exception {
    
		Cipher cipher = getCipherInstance(keyEncAlgo);
	    try {
	    	
	        OAEPParameterSpec oaepParameterSpec = null;
	        if (SecConstants.KEYTRANSPORT_RSAOEP.equals(keyEncAlgo)) {
	            oaepParameterSpec = new OAEPParameterSpec("SHA-1", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT);
	        }
	        
	        if (oaepParameterSpec == null) {
	            cipher.init(Cipher.WRAP_MODE, remoteCert);
	        
	        } else {
	            cipher.init(Cipher.WRAP_MODE, remoteCert.getPublicKey(), oaepParameterSpec);
	        }
	    
	    } catch (InvalidKeyException e) {
	        throw new Exception("Encryption failed: " + e.getMessage());
	        
	    } catch (InvalidAlgorithmParameterException e) {
	        throw new Exception("Encryption failed: " + e.getMessage());

	    }
   
	    try {
	        encryptedEphemeralKey = cipher.wrap(secretKey);
	    
	    } catch (IllegalStateException ex) {
	        throw new Exception("Encryption failed: " + ex.getMessage());
	        
	    } catch (IllegalBlockSizeException ex) {
	        throw new Exception("Encryption failed: " + ex.getMessage());
	        
	    } catch (InvalidKeyException ex) {
	        throw new Exception("Encryption failed: " + ex.getMessage());
	    }

	    //
	    // Now we need to setup the EncryptedKey header block 1) create a
	    // EncryptedKey element and set a wsu:Id for it 2) Generate ds:KeyInfo
	    // element, this wraps the wsse:SecurityTokenReference 3) Create and set
	    // up the SecurityTokenReference according to the keyIdentifier parameter
	    // 4) Create the CipherValue element structure and insert the encrypted
	    // session key
	    //

	    /*
	     * EXAMPLE STRUCTURE
	     *
	     * <wsse:Security>
	     * 	<xenc:EncryptedKey>
	     * 		<xenc:EncryptionMethod Algorithm="…"/>
	     * 		<ds:KeyInfo>
	     * 			<wsse:SecurityTokenReference>
	     * 
	     */
	    
	    this.encryptedKeyElement = createEncryptedKey(this.keyEncAlgo);
	    
	    if (this.encKeyId == null || "".equals(this.encKeyId)) {
	        this.encKeyId = "EK-" + UUIDGenerator.getUUID();
	    }
	    
	   this.encryptedKeyElement.setAttributeNS(null, "Id", this.encKeyId);
	
	    /*
	     * __DESIGN__
	     * 
	     * The actual version of the encryption mechanism exclusively
	     * supports supports a security token reference, that holds
	     * a reference to a binary security token as part of the 
	     * message; the same mechanism is also used with signature
	     */


	    /*
	     * 	<ds:KeyInfo>
		 *		<wsse:SecurityTokenReference>
		 *			<wsse:Reference URI="#urn:oasis:names:tc:ebxmlregrep:rs:security:SenderCert" ValueType="http://docs.oasisopen.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/>
		 * 		</wsse:SecurityTokenReference>
		 */

	   this.keyInfo = createKeyInfo();

	    /*
	     * <xenc:CipherData>
	     * 	<xenc:CipherValue>…</xenc:CipherValue>
	     * </xenc:CipherData>
	     */
	    
	    Text keyText = SecUtil.createBase64EncodedTextNode(this.xmlDoc, encryptedEphemeralKey);
    
	    Element xencCipherValue = createCipherValue(this.encryptedKeyElement);
	    xencCipherValue.appendChild(keyText);

	}

    /*
     * Encrypt one or more parts or elements of the message.
     * 
     * This method takes a vector of WSEncryptionPart object that
     * contain information about the elements to encrypt. The method 
     * call the encryption method, takes the reference information 
     * generated during encryption and add this to the xenc:Reference
     * element.
     */

	public Element encryptForRef(List<SecEncPart> references) throws Exception {

        List<String> encDataRefs = doEncryption(symmetricKey, symEncAlgo, references);

        /*
         *	<xenc:EncryptedKey>
		 *		<xenc:ReferenceList>
		 * 			<xenc:DataReference URI="#encrypted"/>
		 * 		</xenc:ReferenceList>
         */
        
        Element referenceList = this.xmlDoc.createElementNS(SecConstants.ENC_NS, SecConstants.ENC_PRE + ":ReferenceList");
 
        // If we're not placing the ReferenceList in an EncryptedKey structure,
        // then add the ENC namespace

        if (!encryptSymmKey) {
            SecUtil.setNamespace(referenceList, SecConstants.ENC_NS, SecConstants.ENC_PRE);
        
        }
       
        return createDataRefList(referenceList, encDataRefs);
    
	}

    // Perform encryption on the SOAP envelope.

	public List<String> doEncryption(SecretKey secretKey, String encryptionAlgorithm, List<SecEncPart> references) throws Exception {

        XMLCipher xmlCipher = null;
        try {
            xmlCipher = XMLCipher.getInstance(encryptionAlgorithm);

        } catch (XMLEncryptionException ex) {
            throw new Exception("Unsupported encryption algorithm.");
        
        }

        List<String> encDataRef = new ArrayList<String>();
        for (int part = 0; part < references.size(); part++) {

        	SecEncPart encPart = references.get(part);
            
            // Get the data to encrypt.
        	DOMCallbackLookup callbackLookup = new DOMCallbackLookup(this.xmlDoc);
            List<Element> elementsToEncrypt = SecUtil.findElements(encPart, callbackLookup, this.xmlDoc);
            
            if (elementsToEncrypt == null || elementsToEncrypt.size() == 0) {
                throw new Exception("Encryption failed.");
            }

            String modifier = encPart.getEncModifier();
            for (Element elementToEncrypt:elementsToEncrypt) {
            
            	String id = encryptElement(elementToEncrypt, modifier, xmlCipher, secretKey);

                encPart.setEncId(id);
                encDataRef.add("#" + id);
            
            }
                
            /**
             * 
             * TODO: not sure, what this functionality is good for
             * 
             * if (part != (references.size() - 1)) {
             *   
             *	try {
             *       this.keyInfo = new KeyInfo((Element) this.keyInfo.getElement().cloneNode(true), null);
             *   
             *	} catch (Exception ex) {
             *       throw new Exception("Encryption failed.");
             *   }
             * 
             * }
             **/
            
        }
        
        return encDataRef;
    
	}

    // Encrypt an element.

	private String encryptElement(Element elementToEncrypt, String modifier, XMLCipher xmlCipher, SecretKey secretKey) throws Exception {

        boolean content = "Content".equals(modifier) ? true : false;

        // Encrypt data, and set necessary attributes in xenc:EncryptedData

        String xencEncryptedDataId = SecUtil.getIdAllocator().createId("ED-", elementToEncrypt);

        try {
            
        	String headerId = "";
            if ("Header".equals(modifier)) {
            	
                Element elem = this.xmlDoc.createElementNS(SecConstants.WSSE11_NS, "wsse11:" + SecConstants.ENCRYPTED_HEADER);
                SecUtil.setNamespace(elem, SecConstants.WSSE11_NS, SecConstants.WSSE11_PRE);
                
                String wsuPrefix = SecUtil.setNamespace(elem, SecConstants.WSU_NS, SecConstants.WSU_PRE);
                
                headerId = SecUtil.getIdAllocator().createId("EH-", elementToEncrypt);
                elem.setAttributeNS(SecConstants.WSU_NS, wsuPrefix + ":Id", headerId);
                
                // Add the EncryptedHeader node to the element to be encrypted's parent
                // (i.e. the SOAP header). Add the element to be encrypted to the Encrypted
                // Header node as well

                Node parent = elementToEncrypt.getParentNode();
                
                elementToEncrypt = (Element)parent.replaceChild(elem, elementToEncrypt);
                elem.appendChild(elementToEncrypt);
                
                NamedNodeMap map = elementToEncrypt.getAttributes();
                for (int i = 0; i < map.getLength(); i++) {
                
                	Attr attr = (Attr)map.item(i);
                    if (attr.getNamespaceURI().equals(SecConstants.URI_SOAP11_ENV) || attr.getNamespaceURI().equals(SecConstants.URI_SOAP12_ENV)) {                         
                        
                    	String soapEnvPrefix = SecUtil.setNamespace(elem, attr.getNamespaceURI(), SecConstants.SOAP_PRE);
                        elem.setAttributeNS(attr.getNamespaceURI(), soapEnvPrefix + ":" + attr.getLocalName(), attr.getValue());
                    
                    }
                }
            }
            
            xmlCipher.init(XMLCipher.ENCRYPT_MODE, secretKey);
            
            EncryptedData encData = xmlCipher.getEncryptedData();
            
            encData.setId(xencEncryptedDataId);
            encData.setKeyInfo(this.keyInfo);
            
            xmlCipher.doFinal(this.xmlDoc, elementToEncrypt, content);
            return xencEncryptedDataId;
        
        } catch (Exception ex) {
            throw new Exception("Encryprtion failed.");
            
        }
        
    }

    // Create DOM subtree for <xenc:EncryptedKey>

	public Element createDataRefList(Element referenceList, List<String> encDataRefs) {
        
		for (String dataReferenceUri:encDataRefs) {
			
            Element dataReference = this.xmlDoc.createElementNS(SecConstants.ENC_NS, SecConstants.ENC_PRE + ":DataReference");
            
            dataReference.setAttributeNS(null, "URI", dataReferenceUri);
            referenceList.appendChild(dataReference);
        
		}
        
		return referenceList;
    
	}

    private KeyInfo createKeyInfo() throws Exception {

        KeyInfo keyInfo = new KeyInfo(this.xmlDoc);
       
        Element keyInfoElement = keyInfo.getElement();
        keyInfoElement.setAttributeNS(SecConstants.XMLNS_NS, "xmlns:" + SecConstants.SIG_PRE, SecConstants.SIG_NS);

	    /*
	     * __DESIGN__
	     * 
	     * The actual version of the encryption mechanism exclusively
	     * supports supports a security token reference, that holds
	     * a reference to a binary security token as part of the 
	     * message; the same mechanism is also used with signature
	     */

	    /*
		 *	<wsse:SecurityTokenReference>
		 *		<wsse:Reference URI="#urn:oasis:names:tc:ebxmlregrep:rs:security:SenderCert" ValueType="http://docs.oasisopen.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/>
		 * 	</wsse:SecurityTokenReference>
		 */
	    
	    Element secToken = createSTR(this.xmlDoc);    
	    keyInfoElement.appendChild(secToken);
    
	    this.encryptedKeyElement.appendChild(keyInfoElement);
	    return keyInfo;
    
    }

	private KeyGenerator getKeyGenerator() throws Exception {

		// Assume AES as default, so initialize it
    
		try {
			
	        String keyAlgorithm = JCEMapper.getJCEKeyAlgorithmFromURI(symEncAlgo);
	        
	        if (keyAlgorithm == null || "".equals(keyAlgorithm)) {
	            keyAlgorithm = JCEMapper.translateURItoJCEID(symEncAlgo);
	        }
	
	        KeyGenerator keyGen = KeyGenerator.getInstance(keyAlgorithm);
	        
	        if (symEncAlgo.equalsIgnoreCase(SecConstants.AES_128) || symEncAlgo.equalsIgnoreCase(SecConstants.AES_128_GCM)) {
	            keyGen.init(128);
	        
	        } else if (symEncAlgo.equalsIgnoreCase(SecConstants.AES_192) || symEncAlgo.equalsIgnoreCase(SecConstants.AES_192_GCM)) {
	            keyGen.init(192);
	        
	        } else if (symEncAlgo.equalsIgnoreCase(SecConstants.AES_256) || symEncAlgo.equalsIgnoreCase(SecConstants.AES_256_GCM)) {
	            keyGen.init(256);
	        }
	        
	        return keyGen;
    
		} catch (NoSuchAlgorithmException e) {
			throw new Exception("[KEY GENERATOR] Unsupported algorithm.");
		}
		
    }

    /*
     * Create DOM subtree for <code>xenc:EncryptedKey</code>
     */
 
	protected Element createEncryptedKey(String keyTransportAlgo) {
		
        Element encryptedKey = this.xmlDoc.createElementNS(SecConstants.ENC_NS, SecConstants.ENC_PRE + ":EncryptedKey");

        SecUtil.setNamespace(encryptedKey, SecConstants.ENC_NS, SecConstants.ENC_PRE);
        Element encryptionMethod = this.xmlDoc.createElementNS(SecConstants.ENC_NS, SecConstants.ENC_PRE + ":EncryptionMethod");

        encryptionMethod.setAttributeNS(null, "Algorithm", keyTransportAlgo);
        encryptedKey.appendChild(encryptionMethod);
        
        return encryptedKey;
    
	}

    private Element createCipherValue(Element encryptedKey) {
        
    	Element cipherData  = this.xmlDoc.createElementNS(SecConstants.ENC_NS, SecConstants.ENC_PRE + ":CipherData");
        Element cipherValue = this.xmlDoc.createElementNS(SecConstants.ENC_NS, SecConstants.ENC_PRE + ":CipherValue");
        
        cipherData.appendChild(cipherValue);
        encryptedKey.appendChild(cipherData);
        
        return cipherValue;
    
    }

    // Convert the raw key bytes into a SecretKey object of type symEncAlgo.

	private static SecretKey prepareSecretKey(String symEncAlgo, byte[] rawKey) {
 
		// Do an additional check on the keysize required by the encryption algorithm
        int size = 0;
        try {
            size = JCEMapper.getKeyLengthFromURI(symEncAlgo) / 8;
        
        } catch (Exception e) {
            // ignore - some unknown (to JCEMapper) encryption algorithm

        }
        
        String keyAlgorithm = JCEMapper.getJCEKeyAlgorithmFromURI(symEncAlgo);
        SecretKeySpec keySpec;
        
        if (size > 0) {
            keySpec = new SecretKeySpec(rawKey, 0, ((rawKey.length > size) ? size : rawKey.length), keyAlgorithm);
        
        } else {
            keySpec = new SecretKeySpec(rawKey, keyAlgorithm);
        }
        
        return (SecretKey)keySpec;
    
	}

    /*
     * Translate the "cipherAlgo" URI to a JCE ID, and return 
     * a javax.crypto.Cipher instance of this type. 
     */
	
    public static Cipher getCipherInstance(String cipherAlgo) throws Exception {

    	try {
            String keyAlgorithm = JCEMapper.translateURItoJCEID(cipherAlgo);
            return Cipher.getInstance(keyAlgorithm);
        
    	} catch (NoSuchPaddingException ex) {
            throw new Exception("Unsupported algorithm: " + cipherAlgo);

    	} catch (NoSuchAlgorithmException ex) {

    		// Check to see if an RSA OAEP MGF-1 with SHA-1 algorithm was 
    		// requested. Some JDKs don't support RSA/ECB/OAEPPadding
            
    		if (SecConstants.KEYTRANSPORT_RSAOEP.equals(cipherAlgo)) {
                
    			try {
                    return Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
                
    			} catch (Exception e) {
    	            throw new Exception("Unsupported algorithm: " + cipherAlgo);
                }

    		} else {
	            throw new Exception("Unsupported algorithm: " + cipherAlgo);

    		}
        }
    }

}

