package de.kp.wsclient.xml;

import java.io.OutputStream;
import java.util.Properties;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;

import de.kp.wsclient.util.StringOutputStream;


public class XMLSerializer {
	
	public static String serialize(Document xmlDoc)  {
		
        String xml = null;
        try {
        	
            TransformerFactory factory = TransformerFactory.newInstance();
            Transformer transformer = factory.newTransformer();
	            
            Properties outFormat = new Properties();
            
            // IMPORTANT: it is essential, that no indents are to be created, as this 
            // this corrupts the signature element; this situation MUST be avoided
            // by using no indentation
            
            outFormat.setProperty( OutputKeys.INDENT, "no" );
	        
            outFormat.setProperty( OutputKeys.METHOD, "xml" );
	        outFormat.setProperty( OutputKeys.OMIT_XML_DECLARATION, "no" );
	        
            outFormat.setProperty( OutputKeys.VERSION, "1.0" );
            outFormat.setProperty( OutputKeys.ENCODING, "UTF-8" );
            
            transformer.setOutputProperties( outFormat );

	        DOMSource domSource = new DOMSource(xmlDoc.getDocumentElement());
            OutputStream output = new StringOutputStream();
            
            StreamResult result = new StreamResult( output );
            transformer.transform( domSource, result );

            xml = output.toString();

        } catch (TransformerConfigurationException e) {
            e.printStackTrace();
        
        } catch (TransformerException e) {
            e.printStackTrace();
        }

        return xml;

	}

}
