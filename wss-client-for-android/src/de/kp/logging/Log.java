package de.kp.logging;

public class Log {

	 private String tag;
	 
	 private boolean debugEnabled = false;
	 
	 public Log(Class<?> clazz) {		 
		 this.tag = clazz.getSimpleName();	 
	 }
	 
	 public boolean isDebugEnabled() {
		 return this.debugEnabled;
	 }
	 
	 public void debug(String message) {
		 android.util.Log.d(tag, message);
	 }

	 public void debug(String message, Exception e) {
		 android.util.Log.d(tag, message, e);
	 }

	 public void debug(Exception e) {
		 android.util.Log.d(tag, "", e);
	 }

	 public void error(Exception e) {
		 android.util.Log.e(tag, "", e);
	 }
	 
	 public void error(String message) {
		 android.util.Log.e(tag, message);
	 }

	 public void error(String message, Exception e) {
		 android.util.Log.e(tag, message, e);
	 }

	 public void warn(String message) {
		 android.util.Log.w(tag, message);
	 }
	 
	 public void warn(String message, Throwable e) {
		 android.util.Log.w(tag, message, e);
	 }
	
}
