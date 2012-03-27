package de.kp.logging;

public class LogFactory {

	public static Log getLog(Class<?> clazz) {
		return new Log(clazz);
	}
}
