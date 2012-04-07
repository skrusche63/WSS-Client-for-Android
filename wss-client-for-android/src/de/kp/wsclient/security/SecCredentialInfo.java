package de.kp.wsclient.security;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.X509Certificate;

import de.kp.wsclient.R;

import android.content.Context;

public class SecCredentialInfo {

	private X509Certificate certificate;
	private PrivateKey privateKey;
	
	private Context context;
	
	private static String KEYSTORE_TYPE = "BKS";
	
	public SecCredentialInfo(Context context, String alias, String keypass) {
		
		this.context = context;
		try {
			loadCredentials(alias, keypass);

		} catch (KeyStoreException e) {
			// do nothing
		}

	}
	
	public SecCredentialInfo(X509Certificate certificate, PrivateKey privateKey) {
		this.certificate = certificate;
		this.privateKey = privateKey;
		
	}
	
	public PrivateKey getPrivateKey() {
		return this.privateKey;
	}
	
	public X509Certificate getCertificate() {
		return this.certificate;
	}
	
	// this method retrieves the credentials from a keystore
	private void loadCredentials(String alias, String password) throws KeyStoreException {
		
		// get a keystore of the Bouncy Castle KeyStore format
		KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
		
		// Get the raw resource, which contains the keystore with
        // your trusted certificates (root and any intermediate certs)
        InputStream is = context.getResources().openRawResource(R.raw.wssc_keystore);

        try {  
        	
        	char[] keypass = password.toCharArray();
 
            // get certificate
            if (keyStore.containsAlias(alias))
            	this.certificate = (X509Certificate) keyStore.getCertificate(alias);
 
			 // get private key
		    KeyStore.PrivateKeyEntry privateKeyEntry;
			try {
			
				privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, new KeyStore.PasswordProtection(keypass));
			    this.privateKey = privateKeyEntry.getPrivateKey();

			} catch (NoSuchAlgorithmException e) {
				// do nothing
			} catch (UnrecoverableEntryException e) {
				// do nothing
			}

            
        } finally {  
               
        	try {
				is.close();
			
        	} catch (IOException e) {
				e.printStackTrace();
			} 
               
        }
        
	}
}
