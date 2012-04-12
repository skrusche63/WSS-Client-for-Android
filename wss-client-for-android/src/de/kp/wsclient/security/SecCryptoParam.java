package de.kp.wsclient.security;

public class SecCryptoParam {
	private int resource;
	private String password;
	private String type = "BKS";
	
	public SecCryptoParam(int resource, String password) {
		this.resource = resource;
		this.password = password;
	}
	
	
	public int getResource() {
		return resource;
	}
	public void setResource(int resource) {
		this.resource = resource;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public String getType() {
		return type;
	}
	public void setType(String type) {
		this.type = type;
	}
	
	
}
