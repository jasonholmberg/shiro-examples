/**
 * 
 */
package str.shiro.auth;

/**
 * @author Jason Holmberg
 *
 */
public class AuthInfo {
  
  private final boolean isAuthenticated;
  private final AuthMessage message;
  
  public AuthInfo(boolean isAuthenticated, AuthMessage message) {
    super();
    this.isAuthenticated = isAuthenticated;
    this.message = message;
  }

  public boolean isAuthenticated() {
    return isAuthenticated;
  }

  public AuthMessage getMessage() {
    return message;
  }
  
}
