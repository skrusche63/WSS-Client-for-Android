package de.kp.wsclient.soap;

import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.scheme.SocketFactory;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.entity.BufferedHttpEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;

import android.content.Context;
import de.kp.wsclient.security.SecCryptoParam;
import de.kp.wsclient.security.SecCryptoParams;

/**
 * Implementation of {@link SOAPSender}, using the Apache HTTP Client
 *
 * This class is an adapted version of the ApacheSOAPRequestor class 
 * from the icesoap project from Alex Gillerian
 * 
 * @author Alex Gilleran
 * 
 * @author Stefan Krusche (krusche@dr-kruscheundpartner.de)
 * @author Peter Arwanitis (arwanitis@dr-kruscheundpartner.de)
 * 
 */

public class SOAPSenderImpl implements SOAPSender {

	/** Soap action to use if none is specified. */
	private static final String BLANK_SOAP_ACTION = "";

	/** Port for HTTPS communication */
	private static final int DEFAULT_HTTPS_PORT = 443;

	/** Port for HTTP communication */
	private static final int DEFAULT_HTTP_PORT = 80;

	/** Name of HTTPS */
	private static final String HTTPS_NAME = "https";

	/** Name of HTTP */
	private static final String HTTP_NAME = "http";

	/** HTTP content type submitted in HTTP POST request for SOAP calls */
	private static final String XML_CONTENT_TYPE = "text/xml; charset=UTF-8";

	/** Label for content-type header */
	private static final String CONTENT_TYPE_LABEL = "Content-type";

	/** Key for SOAP action header */
	private static final String HEADER_KEY_SOAP_ACTION = "SOAPAction";

	/** Timeout for making a connection */
	private static final int DEFAULT_CONN_TIMEOUT = 5000;

	/** Timeout for recieving data */
	private static final int DEFAULT_SOCKET_TIMEOUT = 20000;

	/** Apache HTTP Client for making HTTP requests */
	private HttpClient httpClient = null;

	/** reference to keystore and truststore */
	private KeyStore keyStore;
	private KeyStore trustStore;

	private Context context;

	private SecCryptoParam trustStoreParam;
	private SecCryptoParam keyStoreParam;

	public SOAPSenderImpl() {
		this(null);
	}	
	
	public SOAPSenderImpl(Context context) {
		this.context = context;
	}
	
	/**
	 * {@inheritDoc}
	 * @throws Exception 
	 */
	@Override
	public SOAPResponse doSoapRequest(SOAPMessage message, String targetUrl) throws Exception {
		return doSoapRequest(message, targetUrl, BLANK_SOAP_ACTION);
	}

	/**
	 * {@inheritDoc}
	 * @throws Exception 
	 */
	public SOAPResponse doSoapRequest(SOAPMessage message, String url, String soapAction) throws Exception {
		return doHttpPost(buildPostRequest(url, message.toXML(), soapAction));
	}

	/**
	 * Performs an HTTP POST request
	 * 
	 * @param httpPost
	 *            The {@link HttpPost} to perform.
	 * @return An {@link InputStream} of the response.
	 * @throws Exception 
	 * @throws SOAPException
	 */

	private SOAPResponse doHttpPost(HttpPost httpPost) throws Exception {

		// lazy initialization
		if (httpClient == null)
			httpClient = buildHttpClient();

		// Execute HTTP Post Request
		HttpResponse response = httpClient.execute(httpPost);
		HttpEntity res = new BufferedHttpEntity(response.getEntity());

		return new SOAPResponse(res.getContent(), response.getStatusLine().getStatusCode());

	}

	/**
	 * Lazy initialization of Android context for resource accessing
	 * 
	 * @param keyStoreParam
	 * @param trustStoreParam
	 * @throws Exception
	 */
	public void init(SecCryptoParams cryptoParams) throws Exception {
		
		// the key- and truststore params are registered for later use
		keyStoreParam   = cryptoParams.get(SecCryptoParams.KEYSTORE);
		trustStoreParam = cryptoParams.get(SecCryptoParams.TRUSTSTORE);
		
		loadKeyStore();
		loadTrustStore();
		
	}

	protected void loadKeyStore() throws Exception {

		InputStream keyStoreStream = context.getResources().openRawResource(keyStoreParam.getResource());
		keyStore = KeyStore.getInstance(keyStoreParam.getType());

		try {
			keyStore.load(keyStoreStream, keyStoreParam.getPassword().toCharArray());
		
		} finally {
			keyStoreStream.close();
		}

	}

	protected void loadTrustStore() throws Exception {

		InputStream trustStoreStream = context.getResources().openRawResource(trustStoreParam.getResource());
		trustStore = KeyStore.getInstance(trustStoreParam.getType());

		try {
			trustStore.load(trustStoreStream, trustStoreParam.getPassword().toCharArray());

		} finally {
			trustStoreStream.close();
		}

	}

	/**
	 * Builds an Apache {@link HttpClient} from defaults.
	 * 
	 * @return An implementation of {@link HttpClient}
	 * @throws Exception 
	 */
	private HttpClient buildHttpClient() throws Exception {

		HttpParams httpParameters = new BasicHttpParams();
		HttpConnectionParams.setConnectionTimeout(httpParameters, DEFAULT_CONN_TIMEOUT);

		HttpConnectionParams.setSoTimeout(httpParameters, DEFAULT_SOCKET_TIMEOUT);
		SchemeRegistry schemeRegistry = getSchemeRegistry();

		ThreadSafeClientConnManager cm = new ThreadSafeClientConnManager(httpParameters, schemeRegistry);
		return new DefaultHttpClient(cm, httpParameters);

	}

	/**
	 * Builds a {@link SchemeRegistry}, which determines the
	 * {@link SocketFactory} that will be used for different ports.
	 * 
	 * This is very important because it will need to be overridden by an
	 * extension class if custom ports or factories (which are used for
	 * self-signed certificates) are to be used.
	 * 
	 * @return A {@link SchemeRegistry} with the necessary port and factories
	 *         registered.
	 * @throws Exception 
	 */
	protected SchemeRegistry getSchemeRegistry() throws Exception {

		SchemeRegistry schemeRegistry = new SchemeRegistry();

		schemeRegistry.register(new Scheme(HTTP_NAME, PlainSocketFactory.getSocketFactory(), DEFAULT_HTTP_PORT));
		schemeRegistry.register(new Scheme(HTTPS_NAME, CertClientSslSocketFactory(), DEFAULT_HTTPS_PORT));

		return schemeRegistry;

	}

	/**
	 * Initializes a SSLSocketFactory ready for mutual authentication via https CLIENT-CERT 
	 * 
	 * @return
	 * @throws Exception 
	 */
	private SSLSocketFactory CertClientSslSocketFactory() throws Exception {
		/*
		 Pass the keystore to the SSLSocketFactory. The factory is
		 responsible
		 for the verification of the server certificate.
		 */
	
		if ((keyStore == null) || (trustStore == null))
			throw new Exception("[SOAPSenderImpl] keystore initialization missing");
		
		SSLSocketFactory socketFactory = new SSLSocketFactory(SSLSocketFactory.TLS, // String algorithm
				keyStore, 					 // KeyStore keystore
				keyStoreParam.getPassword(), // String keystorePassword
				trustStore, 				 // KeyStore truststore
				null, 						 // SecureRandom random
				null 						 // HostNameResolver nameResolver
		);

		// Hostname verification from certificate
		// http://hc.apache.org/httpcomponents-client-ga/tutorial/html/connmgmt.html#d4e506
		socketFactory.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER); // .STRICT_HOSTNAME_VERIFIER);
		return socketFactory;
			
	}

	/**
	 * Builds an {@link HttpPost} request.
	 * 
	 * @param url
	 *            the URL to POST to
	 * @param envelopeString
	 *            The envelope to post, as a serialized string.
	 * @param soapAction
	 *            SOAPAction for the header.
	 * @return An {@link HttpPost} object representing the supplied information.
	 * @throws UnsupportedEncodingException
	 */
	private HttpPost buildPostRequest(String url, String envelopeString, String soapAction)
			throws UnsupportedEncodingException {

		// Create a new HttpClient and Post Header
		HttpPost httppost = new HttpPost(url);

		httppost.setHeader(CONTENT_TYPE_LABEL, XML_CONTENT_TYPE);
		httppost.setHeader(HEADER_KEY_SOAP_ACTION, soapAction);

		HttpEntity entity = new StringEntity(envelopeString);

		httppost.setEntity(entity);
		return httppost;

	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void setConnectionTimeout(int timeout) {
		HttpConnectionParams.setConnectionTimeout(httpClient.getParams(), timeout);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void setSocketTimeout(int timeout) {
		HttpConnectionParams.setSoTimeout(httpClient.getParams(), timeout);
	}
}
