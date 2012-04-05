package de.kp.wsclient.security;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.xml.security.utils.Base64;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import de.kp.wsclient.soap.SOAP11Constants;
import de.kp.wsclient.soap.SOAP12Constants;
import de.kp.wsclient.soap.SOAPConstants;
import de.kp.wsclient.util.UUIDGenerator;

public class SecUtil {

    /*
     * The default wsu:Id allocator is a simple "start at 1 and increment up"
     * thing that is very fast.
     */

    private static WsuIdAllocator idAllocator = new WsuIdAllocator() {
 
    	int i;
        private synchronized String next() {
            return Integer.toString(++i);
        }
        public String createId(String prefix, Object o) {
            if (prefix == null) {
                return next();
            }
            return prefix + next();
        }

        public String createSecureId(String prefix, Object o) {
            if (prefix == null) {
                return UUIDGenerator.getUUID();
            }
            return prefix + UUIDGenerator.getUUID();
        }
    };

    // A cached MessageDigest object
    private static MessageDigest digest = null;
    
    public static WsuIdAllocator getIdAllocator() {
        return idAllocator;
    }

    public static SOAPConstants getSOAPConstants(Element startElement) {

    	Document doc = startElement.getOwnerDocument();
        String ns = doc.getDocumentElement().getNamespaceURI();
        
        if (SecConstants.URI_SOAP12_ENV.equals(ns)) {
            return new SOAP12Constants();
        }
        
        return new SOAP11Constants();
    
    }

    // create a base64 test node <p/>

    public static Text createBase64EncodedTextNode(Document doc, byte data[]) {
        return doc.createTextNode(Base64.encode(data));
    }
   
    public static String getSOAPNamespace(Element startElement) {
        return getSOAPConstants(startElement).getEnvelopeURI();
    }

    public static Element prependChildElement(Element parent, Element child) {
        
    	Node firstChild = parent.getFirstChild();
        if (firstChild == null) {
            return (Element)parent.appendChild(child);
        
        } else {
            return (Element)parent.insertBefore(child, firstChild);
        
        }
    }

    /*
     * Generate a (SHA1) digest of the input bytes. The MessageDigest 
     * instance that backs this method is cached for efficiency.  
     */

    public static synchronized byte[] generateDigest(byte[] inputBytes) throws Exception {
        
    	try {
        
    		if (digest == null) digest = MessageDigest.getInstance("SHA-1");
    		return digest.digest(inputBytes);
        
    	} catch (Exception e) {
            throw new Exception("[SecUtil] Error in generating digest");
            
        }
    }

    /*
     * Set a namespace/prefix on an element if it is not set already. 
     * First off, it searches for the element for the prefix associated 
     * with the specified namespace. If the prefix isn't null, then this 
     * is returned. Otherwise, it creates a new attribute using the 
     * namespace/prefix passed as parameters.
     */

    public static String setNamespace(Element element, String namespace, String prefix) {
    
    	String pre = getPrefixNS(namespace, element);
        if (pre != null) {
            return pre;
        }
        
        element.setAttributeNS(SecConstants.XMLNS_NS, "xmlns:" + prefix, namespace);
        return prefix;
    
    }

    // The following methods were copied over from axis.utils.XMLUtils and adapted

    public static String getPrefixNS(String uri, Node e) {

    	while (e != null && (e.getNodeType() == Element.ELEMENT_NODE)) {
        
    		NamedNodeMap attrs = e.getAttributes();
            for (int n = 0; n < attrs.getLength(); n++) {
            
            	Attr a = (Attr) attrs.item(n);
                String name = a.getName();
                
                if (name.startsWith("xmlns:") && a.getNodeValue().equals(uri)) {
                    return name.substring(6);
                }
            
            }
            
            e = e.getParentNode();
        
    	}
        return null;
    }

    // return the first soap "Body" element.
    
    public static Element findBodyElement(Document doc) {
    
    	//
        // Find the SOAP Envelope NS. Default to SOAP11 NS
        //
        Element docElement = doc.getDocumentElement();
        String ns = docElement.getNamespaceURI();
        return getDirectChildElement(docElement, SecConstants.ELEM_BODY, ns);

    }

    // Gets a direct child with specified localname and namespace. <p/>

    public static Element getDirectChildElement(Node parentNode, String localName, String namespace) {
        
    	if (parentNode == null) {
            return null;
        }
        
    	for (Node currentChild = parentNode.getFirstChild();  currentChild != null;  currentChild = currentChild.getNextSibling()) {
            
    		if (Node.ELEMENT_NODE == currentChild.getNodeType() && localName.equals(currentChild.getLocalName()) && namespace.equals(currentChild.getNamespaceURI())) {
                return (Element)currentChild;
            }
        }
    	
        return null;
    }

    /*
     * Find the DOM Element in the SOAP Envelope that is referenced by the 
     * WSEncryptionPart argument. 
     * 
     * The "Id" is used before the Element localname/namespace.
     */

    public static List<Element> findElements(WSEncryptionPart part, CallbackLookup callbackLookup, Document doc) throws Exception {

    	// See if the DOM Element is stored in the WSEncryptionPart first
        if (part.getElement() != null) {
            return Collections.singletonList(part.getElement());
        }
        
        // Next try to find the Element via its wsu:Id
        String id = part.getId();
        if (id != null) {
            Element foundElement = callbackLookup.getElement(id, null, false);
            return Collections.singletonList(foundElement);
        }
        
        // Otherwise just lookup all elements with the localname/namespace
        return callbackLookup.getElements(part.getName(), part.getNamespace());
    }

    /*
     * Returns all elements that match name and namespace. 
     */
 
    public static List<Element> findElements(Node startNode, String name, String namespace) {

    	// Replace the formerly recursive implementation with a 
    	// depth-first-loop lookup

    	if (startNode == null) {
            return null;
        }
        
    	Node startParent = startNode.getParentNode();
        Node processedNode = null;

        List<Element> foundNodes = new ArrayList<Element>();
        while (startNode != null) {
 
        	// start node processing at this point
            if (startNode.getNodeType() == Node.ELEMENT_NODE && startNode.getLocalName().equals(name)) {
 
            	String ns = startNode.getNamespaceURI();
                if (ns != null && ns.equals(namespace)) {
                    foundNodes.add((Element)startNode);
                }

                if ((namespace == null || namespace.length() == 0) && (ns == null || ns.length() == 0)) {
                    foundNodes.add((Element)startNode);
                }
            }
 
            processedNode = startNode;
            startNode = startNode.getFirstChild();

            // no child, this node is done.
            if (startNode == null) {
                // close node processing, get sibling
                startNode = processedNode.getNextSibling();
            }
            
            // no more siblings, get parent, all children
            // of parent are processed.
            while (startNode == null) {
                processedNode = processedNode.getParentNode();
                if (processedNode == startParent) {
                    return foundNodes;
                }
                // close parent node processing (processed node now)
                startNode = processedNode.getNextSibling();
            }
        }
        
        return foundNodes;
    }

    /*
     * Returns the single element that contains an Id with value
     * uri and namespace. The Id can be either a wsu:Id or an Id
     * with no namespace. This is a replacement for a XPath Id 
     * lookup with the given namespace. 
     * 
     * It's somewhat faster than XPath, and we do not deal with 
     * prefixes, just with the real namespace URI
     * 
     * If checkMultipleElements is true and there are multiple 
     * elements, we log a warning and return null as this can 
     * be used to get around the signature checking.
     */

    public static Element findElementById(Node startNode, String value, boolean checkMultipleElements) {

    	//
        // Replace the formerly recursive implementation with a depth-first-loop lookup
        //
        Node startParent = startNode.getParentNode();
        Node processedNode = null;
        Element foundElement = null;
        String id = getIDFromReference(value);

        while (startNode != null) {
            // start node processing at this point
            if (startNode.getNodeType() == Node.ELEMENT_NODE) {
                Element se = (Element) startNode;
                // Try the wsu:Id first
                String attributeNS = se.getAttributeNS(SecConstants.WSU_NS, "Id");
                if ("".equals(attributeNS) || !id.equals(attributeNS)) {
                    attributeNS = se.getAttributeNS(null, "Id");
                }
                if (!"".equals(attributeNS) && id.equals(attributeNS)) {

                	if (!checkMultipleElements) {
                        return se;
                    
                	} else if (foundElement == null) {
                        foundElement = se; // Continue searching to find duplicates
                    
                	} else {
                        return null;
                    }
                }
            }

            processedNode = startNode;
            startNode = startNode.getFirstChild();

            // no child, this node is done.
            if (startNode == null) {
                // close node processing, get sibling
                startNode = processedNode.getNextSibling();
            }
            // no more siblings, get parent, all children
            // of parent are processed.
            while (startNode == null) {
                processedNode = processedNode.getParentNode();
                if (processedNode == startParent) {
                    return foundElement;
                }
                // close parent node processing (processed node now)
                startNode = processedNode.getNextSibling();
            }
        }
        return foundElement;
    }

    /*
     * Turn a reference (eg "#5") into an ID (eg "5").
     */
 
    public static String getIDFromReference(String ref) {
 
    	String id = ref.trim();
        if (id.length() == 0) {
            return null;
        }
        if (id.charAt(0) == '#') {
            id = id.substring(1);
        }
        return id;
    }

}
