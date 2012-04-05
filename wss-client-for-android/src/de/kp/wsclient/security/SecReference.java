/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package de.kp.wsclient.security;

import javax.xml.namespace.QName;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Reference.
 * 
 * @author Davanum Srinivas (dims@yahoo.com).
 * @author Stefan Krusche (krusche@dr-kruscheundpartner.de)
 */

// this class is an adapted version from the WSS4j Reference.java

public class SecReference {
	
    public static final QName TOKEN = new QName(SecConstants.WSSE_NS, "Reference");
    protected Element element = null;
    
    /**
     * Constructor.
     * 
     * @param elem The Reference element
     * @throws Exception 
     */
    public SecReference(Element elem) throws Exception {

    	if (elem == null) throw new Exception("[Invalid Security] No reference element provided.");

    	element = elem;
        
    	QName el = new QName(element.getNamespaceURI(), element.getLocalName());
        if (!el.equals(TOKEN)) throw new Exception("[Security Failure] Invalid reference element.");

        String uri = getURI();

        // Reference URI cannot be null or empty
        if (uri == null || "".equals(uri))throw new Exception("[Invalid Security] Bad reference URI.");

    }

    public SecReference(Document doc) {
        element = doc.createElementNS(SecConstants.WSSE_NS, "wsse:Reference");
    }

    /**
     * Get the DOM element.
     * 
     * @return the DOM element
     */
    public Element getElement() {
        return element;
    }

    /**
     * Get the ValueType attribute.
     * 
     * @return the ValueType attribute
     */
    public String getValueType() {
        return element.getAttribute("ValueType");
    }

    /**
     * Get the URI.
     * 
     * @return the URI
     */
    public String getURI() {
        return element.getAttribute("URI");
    }

    /**
     * Set the Value type.
     * 
     * @param valueType the ValueType attribute to set
     */
    public void setValueType(String valueType) {
        element.setAttributeNS(null, "ValueType", valueType);
    }

    /**
     * Set the URI.
     * 
     * @param uri the URI to set
     */
    public void setURI(String uri) {
        element.setAttributeNS(null, "URI", uri);
    }
    
    @Override
    public int hashCode() {
        int result = 17;
        String uri = getURI();
        if (uri != null) {
            result = 31 * result + uri.hashCode();
        }
        String valueType = getValueType();
        if (valueType != null) {
            result = 31 * result + valueType.hashCode();
        }
        return result;
    }
    
    @Override
    public boolean equals(Object object) {
        if (!(object instanceof SecReference)) {
            return false;
        }
        SecReference reference = (SecReference)object;
        if (!compare(getURI(), reference.getURI())) {
            return false;
        }
        if (!compare(getValueType(), reference.getValueType())) {
            return false;
        }
        return true;
    }
    
    private boolean compare(String item1, String item2) {
        if (item1 == null && item2 != null) { 
            return false;
        } else if (item1 != null && !item1.equals(item2)) {
            return false;
        }
        return true;
    }
}
