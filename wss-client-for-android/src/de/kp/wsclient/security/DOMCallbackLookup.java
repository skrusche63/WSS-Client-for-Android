/*
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

import java.util.Collections;
import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/*
 * This class uses a DOM-based approach to locate Elements that are referenced via an Id.
 */

public class DOMCallbackLookup implements CallbackLookup {
    
    protected Document doc;
    
    public DOMCallbackLookup(Document doc) {
        this.doc = doc;
    }

    /*
     * Get the DOM element that corresponds to the given id and ValueType reference. 
     * The Id can be a wsu:Id or else an Id attribute, or a SAML Id when the ValueType 
     * refers to a SAML Assertion.
     */
 
    public Element getElement(String id, String valueType, boolean checkMultipleElements) throws Exception {

    	// Try the SOAP Body next
        Element bodyElement = SecUtil.findBodyElement(doc);
        if (bodyElement != null) {

        	String cId = bodyElement.getAttributeNS(SecConstants.WSU_NS, "Id");
            if (cId.equals(id)) {
                 return bodyElement;
            }
        
        }
        
        // Otherwise do a general search
        return SecUtil.findElementById(doc.getDocumentElement(), id, checkMultipleElements);
    
    }
    
    /*
     * Get the DOM element(s) that correspond to the given 
     * localname/namespace. 
     */

    public List<Element> getElements(String localname, String namespace) throws Exception {
    
        // Try the SOAP Body first
    	Element bodyElement = SecUtil.findBodyElement(doc);
        
    	if (SecConstants.ELEM_BODY.equals(localname) &&
        
			bodyElement.getNamespaceURI().equals(namespace)) {
        	return Collections.singletonList(bodyElement);
        
    	}
    
        return SecUtil.findElements(doc.getDocumentElement(), localname, namespace);
    
    }
}
