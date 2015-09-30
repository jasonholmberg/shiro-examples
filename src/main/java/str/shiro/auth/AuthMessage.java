/**
 * 
 */
package str.shiro.auth;

/**
 * @author Jason Holmberg
 *
 */
public class AuthMessage {
  public static final String MSG_SUCCESS = "Authentication successful";
  public static final String MSG_FAIL = "Authentication failed";
  private final String message;
  private final Exception exception;

  public AuthMessage(String message, Exception exception) {
    super();
    this.message = message;
    this.exception = exception;
  }

  public String getMessage() {
    return message;
  }

  public Exception getException() {
    return exception;
  }
  
}
