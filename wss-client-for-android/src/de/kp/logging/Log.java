package de.kp.logging;

public class Log {

	 private String tag;
	 
	 // xxx pa 120410 force debug
	 private boolean debugEnabled = true;
	 
	 public Log(Class<?> clazz) {		 
		 this.tag = clazz.getSimpleName();	 
	 }
	 
	 public boolean isDebugEnabled() {
		 return this.debugEnabled;
	 }
	 
	 /**
	 * @param message
	 */
	public void debug(String message) {
		 android.util.Log.d(tag, message);
	 }

	 /**
	 * @param message
	 * @param e
	 */
	public void debug(String message, Exception e) {
		 android.util.Log.d(tag, message, e);
	 }

	 /**
	 * @param e
	 */
	public void debug(Exception e) {
		 android.util.Log.d(tag, "", e);
	 }

	 /**
	 * @param e
	 */
	public void error(Exception e) {
		 android.util.Log.e(tag, "", e);
	 }
	 
	 /**
	 * @param message
	 */
	public void error(String message) {
		 android.util.Log.e(tag, message);
	 }

	 /**
	 * @param message
	 * @param e
	 */
	public void error(String message, Exception e) {
		 android.util.Log.e(tag, message, e);
	 }

	 /**
	 * @param message
	 */
	public void warn(String message) {
		 android.util.Log.w(tag, message);
	 }
	 
	 /**
	 * @param message
	 * @param e
	 */
	public void warn(String message, Throwable e) {
		 android.util.Log.w(tag, message, e);
	 }
	
}
