package de.kp.wsclient.security;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
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
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.keys.KeyInfo;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
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

	private SecCrypto crypto;
    
    // Symmetric key used in the EncryptedKey.
    private SecretKey symmetricKey = null;

    // Encrypted bytes of the symmetric key
    private byte[] encryptedSymmetricKey;

    // DEFAULT Algorithm used to encrypt the symmetric key;
    // as an alternative, also KEYTRANSPORT_RSAOEP is supported
    private String keyEncAlgo = SecConstants.KEYTRANSPORT_RSA15;
    
    // DEFAULT Algorithm to be used with the ephemeral key.
    // This parameter determines the key generator.
    private String symEncAlgo = SecConstants.AES_128;

    // xenc:EncryptedKey element
    private Element encryptedKeyElement = null;

    private String encKeyId = null;

    private KeyInfo keyInfo;
    private Document xmlDoc;
	
    /**
     * Constructor SecEncryptor
     * @param crypto
     */
	public SecEncryptor(SecCrypto crypto) {		
		this.crypto = crypto;
	}


	/**
     * This method builds the SOAP envelope with encrypted Body and adds 
     * encrypted key; this method is an adapted version of the WSS4j build 
     * method
	 *
	 * @param xmlDoc (SOAP envelope)
	 * @return
	 * @throws Exception
	 */
	/**
	 * @param xmlDoc
	 * @return
	 * @throws Exception
	 */
	public Document encrypt(Document xmlDoc) throws Exception {
		
		// set reference to xml document as this is used
		// with other encryption methods
		
		this.xmlDoc = xmlDoc;		

		Element soapHeader = getSOAPHeader(xmlDoc);
		if (soapHeader == null) throw new Exception("SOAP Header not found.");

		buildEncKeyElement();
	        
        Element envelope = xmlDoc.getDocumentElement();
        List<SecEncPart> parts = new ArrayList<SecEncPart>();

        String soapNamespace = SecUtil.getSOAPNamespace(envelope);
            
        SecEncPart encP = new SecEncPart(SecConstants.ELEM_BODY, soapNamespace, "Content");
        parts.add(encP);
        
        Element refs = encryptForRef(parts);
        Element secHeader = getSecHeader(this.xmlDoc);
        
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
            SecUtil.prependChildElement(secHeader, encryptedKeyElement);
        
        } else {
            /*
             * Adds (prepends) the external Reference element to the Security header.
             * 
             * The reference element must be created by the encryptForExternalRef
             *  method. The method prepends the reference element in the SecurityHeader.
             */
        	SecUtil.prependChildElement(secHeader, refs);
        
        }
        
        soapHeader.appendChild(secHeader);
        return xmlDoc;
        
    }

	/**
	 * This method generates the symmetric key and also its
	 * encrypted version; to this end, the public key of the
	 * receiver of the SOAP message is used.
	 * 
	 * In addition the <xenc:EncryptedKey> element is built
	 * and added to the <wsse:Security> header
	 * 
	 * @throws Exception
	 */
	private void buildEncKeyElement() throws Exception {
	
		// the subsequent part of code is adapted from the 'prepare'
		// method of WSS4J (1.6.4) WSSecEncrypt
	        
		KeyGenerator keyGen = getKeyGenerator();
		this.symmetricKey = keyGen.generateKey();            
	    
		/*
		 * Encrypt the symmetric key data and prepare the EncryptedKey element
		 * This method does the most work for to prepare the EncryptedKey element.
		 */
		
		Cipher cipher = getCipherInstance(this.keyEncAlgo);
	    try {
	    	
	        OAEPParameterSpec oaepParameterSpec = null;
	        
	        // the default encoding algorithm is SecConstants.KEYTRANSPORT_RSA15
	        if (SecConstants.KEYTRANSPORT_RSAOEP.equals(this.keyEncAlgo)) {
	            oaepParameterSpec = new OAEPParameterSpec("SHA-1", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT);
	        }
	        
	        if (oaepParameterSpec == null) {
	        	// this is the default way to initialize the Cipher instance
	            cipher.init(Cipher.WRAP_MODE, this.crypto.getPublicKey());
	        
	        } else {
	            cipher.init(Cipher.WRAP_MODE, this.crypto.getPublicKey(), oaepParameterSpec);

	        }

	        this.encryptedSymmetricKey = cipher.wrap(this.symmetricKey);

	    } catch (InvalidKeyException e) {
	        throw new Exception("Encryption failed: " + e.getMessage());
	        
	    } catch (InvalidAlgorithmParameterException e) {
	        throw new Exception("Encryption failed: " + e.getMessage());
	    
	    } catch (IllegalStateException e) {
	        throw new Exception("Encryption failed: " + e.getMessage());
	        
	    } catch (IllegalBlockSizeException e) {
	        throw new Exception("Encryption failed: " + e.getMessage());

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
	    
	    this.encryptedKeyElement = createEncKeyElement(this.keyEncAlgo);
	    
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
	    
	    Text keyText = SecUtil.createBase64EncodedTextNode(this.xmlDoc, this.encryptedSymmetricKey);
    
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
        return createDataRefList(referenceList, encDataRefs);
    
	}

	/**
	 * This method encrypts a list of body elements (references)
	 * of the SOAP message 
	 * 
	 * @param secretKey
	 * @param encryptionAlgorithm
	 * @param references
	 * @return
	 * @throws Exception
	 */
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
           
        }
        
        return encDataRef;
    
	}

	/**
	 * This method encrypts a single DOM element.
	 * 
	 * @param elementToEncrypt
	 * @param modifier
	 * @param xmlCipher
	 * @param secretKey
	 * @return
	 * @throws Exception
	 */
	private String encryptElement(Element elementToEncrypt, String modifier, XMLCipher xmlCipher, SecretKey secretKey) throws Exception {

        boolean content = "Content".equals(modifier) ? true : false;
        if (content == false) {
        	throw new Exception("[SecEncryptor] Encryption is actually restricted to content.");
        }

        // Encrypt data, and set necessary attributes in xenc:EncryptedData
        String xencEncryptedDataId = SecUtil.getIdAllocator().createId("ED-", elementToEncrypt);

        try {
             
            // this is the DEFAULT way to encrypt the content,
            // i.e. the body of a SOAP message
            
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
	    
	    // IMPORTANT: The wsse:Namespace MUST be set explicity
	    // to ensure proper validation of signature
	    SecUtil.setNamespace(secToken, SecConstants.WSSE_NS, SecConstants.WSSE_PRE);
	    
	    keyInfoElement.appendChild(secToken);
    
	    this.encryptedKeyElement.appendChild(keyInfoElement);
	    return keyInfo;
    
    }

	private KeyGenerator getKeyGenerator() throws Exception {
   
		try {

			// Algorithm to be used with the ephemeral key::SecConstants.AES_128 (DEFAULT)
			
	        String keyAlgorithm = JCEMapper.getJCEKeyAlgorithmFromURI(this.symEncAlgo);
	        
	        if (keyAlgorithm == null || "".equals(keyAlgorithm)) {
	            keyAlgorithm = JCEMapper.translateURItoJCEID(this.symEncAlgo);
	        }
	
	        KeyGenerator keyGen = KeyGenerator.getInstance(keyAlgorithm);

	        if (this.symEncAlgo.equalsIgnoreCase(SecConstants.AES_128) || this.symEncAlgo.equalsIgnoreCase(SecConstants.AES_128_GCM)) {
	        	// this is the default way to initialize the key generator
	            keyGen.init(128);
	        
	        } else if (this.symEncAlgo.equalsIgnoreCase(SecConstants.AES_192) || this.symEncAlgo.equalsIgnoreCase(SecConstants.AES_192_GCM)) {
	            keyGen.init(192);
	        
	        } else if (this.symEncAlgo.equalsIgnoreCase(SecConstants.AES_256) || this.symEncAlgo.equalsIgnoreCase(SecConstants.AES_256_GCM)) {
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
 
	protected Element createEncKeyElement(String keyTransportAlgo) {
		
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
	
    /**
     * Translate the "cipherAlgo" URI to a JCE ID, and 
     * return a javax.crypto.Cipher instance of this type. 
     * 
     * @param cipherAlgo
     * @return
     * @throws Exception
     */
    public Cipher getCipherInstance(String cipherAlgo) throws Exception {

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

