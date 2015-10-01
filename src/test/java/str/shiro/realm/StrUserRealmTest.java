/**
 * 
 */
package str.shiro.realm;

import static org.junit.Assert.*;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

import java.util.List;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import str.shiro.auth.AuthInfo;
import str.shiro.auth.AuthMessage;
import str.shiro.data.Perms;
import str.shiro.data.Roles;
import str.shiro.data.Users;
import str.shiro.model.User;
import str.shiro.service.UserService;
import str.shiro.service.impl.SecuredMockUserService;

/**
 * @author Jason Holmberg
 *
 */
public class StrUserRealmTest {

  private static final Logger log = LoggerFactory.getLogger(StrUserRealmTest.class); 
  private UserService userService;

  /**
   * @throws java.lang.Exception
   */
  @Before
  public void setUp() throws Exception {
    userService = spy(new SecuredMockUserService());
  }

  @After
  public void tearDown() {
    // Need to do this to make sure each test is run fresh.
    ThreadContext.unbindSubject();
    ThreadContext.unbindSecurityManager();
  }
  
  @Test
  public void authcSuccess() {
    final String username = Users.batman.username;
    final String password = Users.batman.password;
    AuthenticationToken token = mock(AuthenticationToken.class);
    when(token.getPrincipal()).thenReturn(username);
    when(token.getCredentials()).thenReturn(password.toCharArray());
    
    doReturn(new AuthInfo(true, new AuthMessage(AuthMessage.MSG_SUCCESS, null))).when(userService).authenticate(eq(username), eq(password));
    
    Realm realm = new StrUserRealm(userService);
    realm.getAuthenticationInfo(token);
    
    AuthenticationInfo result = realm.getAuthenticationInfo(token);
    assertNotNull(result);
    assertEquals(username, (String) result.getPrincipals().getPrimaryPrincipal());
    assertEquals(password, new String((char[])result.getCredentials()));
  }

  @Test(expected = AuthenticationException.class)
  public void authcFail() {
    final String username = Users.batman.username;
    final String password = Users.batman.password;
    AuthenticationToken token = mock(AuthenticationToken.class);
    when(token.getPrincipal()).thenReturn(username);
    when(token.getCredentials()).thenReturn(password.toCharArray());
    
    doReturn(new AuthInfo(false, new AuthMessage(AuthMessage.MSG_FAIL, new Exception()))).when(userService).authenticate(eq(username), eq(password));
    Realm realm = new StrUserRealm(userService);
    realm.getAuthenticationInfo(token);
    
    realm.getAuthenticationInfo(token);
  }
  
  @Test
  public void authcViaSecurutyManager() {
    final String username = Users.batman.username;
    final String password = Users.batman.password;
    
    Subject currentUser = shiroAuthcHelper(username, password);
    assertTrue(currentUser.isAuthenticated());
    System.out.println(currentUser.getPrincipal());
    currentUser.hasRole(Roles.admin.name());
  }
  
  @Test
  public void authcFailViaSecurutyManager() {
    final String username = Users.batman.username;
    final String password = "bad-password";
    
    try {
      shiroAuthcHelper(username, password);
    } catch (AuthenticationException e) {
      assertFalse(SecurityUtils.getSubject().isAuthenticated());
      assertEquals(AuthMessage.MSG_FAIL, e.getMessage());
    }
  }
  
  @Test
  public void authzTest() {
    Subject currentUser = shiroAuthcHelper(Users.batman.username, Users.batman.password);
    assertTrue(currentUser.hasRole(Roles.admin.name()));
    assertTrue(currentUser.isPermitted(Perms.create.name()));
    
    currentUser.logout();
    currentUser = shiroAuthcHelper(Users.robin.username, Users.robin.password);
    assertFalse(currentUser.hasRole(Roles.admin.name()));
    assertFalse(currentUser.isPermitted(Perms.delete.name()));
  }
  
  @Test
  public void authzTestInServiceSuccess() {
    Subject batman = shiroAuthcHelper(Users.batman.username, Users.batman.password);
    User user = userService.findUser(Users.robin.username);
    assertNotNull(user);
    assertEquals(Users.robin.username, user.getUsername());
  }
  
  @Test
  public void authzTestInServiceInstanceLevel() {
    Subject robin = shiroAuthcHelper(Users.robin.username, Users.robin.password);
    List<User> users = userService.findUsers();
    assertNotNull(users);
    log.debug("Users: {}",users.toString());
    assertTrue(users.size() == 2);
  }
  
  public Subject shiroAuthcHelper(final String username, final String password) {
    AuthorizingRealm realm = new StrUserRealm(userService);
    realm.setCacheManager(new MemoryConstrainedCacheManager());
    SecurityManager securityManager = new DefaultSecurityManager(realm);
    SecurityUtils.setSecurityManager(securityManager);
    Subject currentUser = SecurityUtils.getSubject();
    UsernamePasswordToken token = new UsernamePasswordToken(username, password);
    token.setRememberMe(true);
    currentUser.login(token);
    return currentUser;
  }
}
