package de.kp.wsclient.util;

import java.io.IOException;
import java.io.OutputStream;

public class StringOutputStream extends OutputStream {
    
	private StringBuilder stringBuilder;

    public StringOutputStream() {
    	stringBuilder = new StringBuilder();
    }

    public void write(int b) throws IOException {
    	stringBuilder.append( (char) b );
    }

    public String toString() {
        return stringBuilder.toString();
    }

}
