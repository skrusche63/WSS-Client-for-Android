package de.kp.logging;

public class LogFactory {

	/**
	 * @param clazz
	 * @return
	 */
	public static Log getLog(Class<?> clazz) {
		return new Log(clazz);
	}
}
