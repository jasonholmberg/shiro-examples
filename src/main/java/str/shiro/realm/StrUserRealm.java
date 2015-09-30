/**
 * 
 */
package str.shiro.realm;

import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import str.shiro.auth.AuthInfo;
import str.shiro.service.UserService;

/**
 * @author Jason Holmberg
 *
 */
public class StrUserRealm extends AuthorizingRealm {
  
  private static final transient Logger log = LoggerFactory.getLogger(StrUserRealm.class);
  
  private UserService userService;
  
  public StrUserRealm() {
    super();
  }
  
  StrUserRealm(UserService userService) {
    super();
    this.userService = userService;
  }

  @Override
  protected void onInit() {
    super.onInit();
  }

  @Override
  protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
    log.debug("In doGetAuthenticationInfo");
    String username = (String) token.getPrincipal();
    char[] password = (char[]) token.getCredentials();
    
    SimpleAuthenticationInfo info = null;
    log.debug("Looking up user and testing credentials");
    AuthInfo authInfo = userService.authenticate(username, new String(password));
    if(authInfo.isAuthenticated()) {
      info = new SimpleAuthenticationInfo(username, password, getName());
    } else {
      throw new AuthenticationException(authInfo.getMessage().getMessage(), authInfo.getMessage().getException());
    }
    return info;
  }

  @Override
  protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
    if (principals == null) {
      throw new AuthorizationException("Principal cannot be null.");
    }
    
    String username = (String) getAvailablePrincipal(principals);
    
    SimpleAuthorizationInfo info = null;
    
    try {
      Set<String> roles = userService.getUserRoles(username);
      Set<String> permissions = userService.getPermissions(username);
      info = new SimpleAuthorizationInfo(roles);
      info.setStringPermissions(permissions);
    } catch (Exception e) {
      throw new AuthorizationException("Error authorizing", e);
    }
    
    return info;
  }

}
