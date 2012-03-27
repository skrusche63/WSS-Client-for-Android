package de.kp.wsclient.soap;

import java.io.IOException;


/*
 * This interface is an adapted version of the SOAPRequestor interface
 * from the icesoap project from Alex Gillerian
 */

/**
 * Handles SOAP requests
 * 
 * @author Alex Gilleran
 * @author Stefan Krusche (krusche@dr-kruscheundpartner.de)
 * 
 */
public interface SOAPSender {
    /**
     * Performs a SOAP request
     * 
     * @param envelope
     *            The SOAP message to send
     * @param targetUrl
     *            The url of the SOAP web service to communicate with.
     * @return An InputStream representing the
     * @throws IOException
     */
    public SOAPResponse doSoapRequest(SOAPMessage message, String targetUrl) throws IOException;

    /**
     * Performs a SOAP request
     * 
     * @param envelope
     *            The SOAP message to send
     * @param targetUrl
     *            The url of the SOAP web service to communicate with.
     * @param soapAction
     *            The SOAP Action to perform - this is put in the
     *            <code>SOAPAction</code> field of the outgoing HTTP post.
     * @return An InputStream representing the
     * @throws IOException
     */
    public SOAPResponse doSoapRequest(SOAPMessage message, String targetUrl, String soapAction) throws IOException;

    /**
     * Set the timeout for making connections to the server.
     * 
     * @param timeout
     *            Timeout time in milliseconds.
     */
    public void setConnectionTimeout(int timeout);

    /**
     * Set the timeout for receiving data from the server - note that this takes
     * into account time to establish a connection, send the envelope, wait for
     * the server to process and then recieve it.
     * 
     * @param timeout
     *            Timeout time in milliseconds.
     */
    public void setSocketTimeout(int timeout);
    
}

