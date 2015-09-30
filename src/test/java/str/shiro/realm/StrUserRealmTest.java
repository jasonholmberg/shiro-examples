/**
 * 
 */
package str.shiro.realm;

import static org.junit.Assert.*;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import str.shiro.auth.AuthInfo;
import str.shiro.auth.AuthMessage;
import str.shiro.model.User;
import str.shiro.service.UserService;

/**
 * @author Jason Holmberg
 *
 */
public class StrUserRealmTest {

  @Mock
  private UserService userService;

  /**
   * @throws java.lang.Exception
   */
  @Before
  public void setUp() throws Exception {
    MockitoAnnotations.initMocks(this);
  }

  @After
  public void tearDown() {
    // Need to do this to make sure each test is run fresh.
    ThreadContext.unbindSubject();
    ThreadContext.unbindSecurityManager();
  }
  
  @Test
  public void authSuccess() {
    final String username = "batman";
    final String password = "b4tg1rl";
    AuthenticationToken token = mock(AuthenticationToken.class);
    when(token.getPrincipal()).thenReturn(username);
    when(token.getCredentials()).thenReturn(password.toCharArray());
    
    when(userService.authenticate(eq(username), eq(password))).thenReturn(new AuthInfo(true, new AuthMessage(AuthMessage.MSG_SUCCESS, null)));
    
    Realm realm = new StrUserRealm(userService);
    realm.getAuthenticationInfo(token);
    
    AuthenticationInfo result = realm.getAuthenticationInfo(token);
    assertNotNull(result);
    assertEquals(username, (String) result.getPrincipals().getPrimaryPrincipal());
    assertEquals(password, new String((char[])result.getCredentials()));
  }

  @Test(expected = AuthenticationException.class)
  public void authFail() {
    final String username = "batman";
    final String password = "b4tg1rl";
    AuthenticationToken token = mock(AuthenticationToken.class);
    when(token.getPrincipal()).thenReturn(username);
    when(token.getCredentials()).thenReturn(password.toCharArray());
    
    when(userService.authenticate(eq(username), eq(password))).thenReturn(new AuthInfo(false, new AuthMessage(AuthMessage.MSG_FAIL, new Exception())));
    
    Realm realm = new StrUserRealm(userService);
    realm.getAuthenticationInfo(token);
    
    realm.getAuthenticationInfo(token);
  }
  
  @Test
  public void authViaSecurutyManager() {
    final String username = "batman";
    final String password = "b4tg1rl";
    
    UserService mockUserService = new MockUserService();
    Realm realm = new StrUserRealm(mockUserService);
    SecurityManager securityManager = new DefaultSecurityManager(realm);
    SecurityUtils.setSecurityManager(securityManager);
    Subject currentUser = SecurityUtils.getSubject();
    UsernamePasswordToken token = new UsernamePasswordToken(username, password);
    token.setRememberMe(true);
    currentUser.login(token);
    assertTrue(currentUser.isAuthenticated());
    System.out.println(currentUser.getPrincipal());
    currentUser.hasRole(Roles.admin.name());
  }
  
  @Test
  public void authFailViaSecurutyManager() {
    final String username = "batman";
    final String password = "bad-password";
    
    UserService mockUserService = new MockUserService();
    Realm realm = new StrUserRealm(mockUserService);
    SecurityManager securityManager = new DefaultSecurityManager(realm);
    SecurityUtils.setSecurityManager(securityManager);
    Subject currentUser = SecurityUtils.getSubject();
    UsernamePasswordToken token = new UsernamePasswordToken(username, password);
    token.setRememberMe(true);
    try {
    currentUser.login(token);
    } catch (AuthenticationException e) {
      assertFalse(currentUser.isAuthenticated());
      assertEquals(AuthMessage.MSG_FAIL, e.getMessage());
    }
  }
  
  
  class MockUserService implements UserService {
    
    
    @Override
    public User findUser(String username) {
      // TODO Auto-generated method stub
      return null;
    }

    @Override
    public List<User> findUsers() {
      // TODO Auto-generated method stub
      return null;
    }

    @Override
    public AuthInfo authenticate(String username, String password) {
      Users user = Users.valueOf(username);
      if(user != null && user.password.equals(password)) {
        return new AuthInfo(true, new AuthMessage(AuthMessage.MSG_SUCCESS, null));
      } else {
        return new AuthInfo(false, new AuthMessage(AuthMessage.MSG_FAIL, new Exception("Authentication failed")));
      }
    }

    @Override
    public Set<String> getUserRoles(String username) {
      UsersRoles usersRoles = UsersRoles.valueOf(username);
      Set<String> roles = new HashSet<>();
      for(Roles role : usersRoles.roles) {
        roles.add(role.name());
      }
      return roles;
    }

    @Override
    public Set<String> getPermissions(String username) {
      Set<String> permissions = new HashSet<>();
      for (Roles role : UsersRoles.valueOf(username).roles) {
        for (Perms perm : RolesPerms.valueOf(role.name()).perms) {
          permissions.add(perm.name());
        }
      }
      
      for(Perms perm : UserPerms.valueOf(username).perms) {
        permissions.add(perm.name());
      }
      return permissions;
    }
    
  }
  
  public enum Users {
    batman("b4tg1rl"),
    robin("b4tg1rl"),
    joker("h@rl3y");
    
    public String password;
    Users(String password) {
      this.password = password;
    }
  };
  
  public enum UsersRoles {
    batman(new Roles[] {Roles.admin, Roles.user, Roles.hero}),
    robin(new Roles[] {Roles.user, Roles.hero}),
    joker(new Roles[] {Roles.villian, Roles.user});
    
    public Roles[] roles;
    UsersRoles(Roles[] roles) {
      this.roles = roles;
    }
    
    public Roles[] getRoles(Users user) {
      return valueOf(user.name()).roles;
    }
  };
  
  public enum Roles {
    admin,
    hero,
    user,
    villian;
  }
  
  public enum Perms {
    read,write,create,delete;
    public static Perms[] all() {
      return Perms.values();
    }
  }
  
  public enum RolesPerms {
    admin(Perms.all()),
    hero(new Perms[] {Perms.read,Perms.write}),
    user(Perms.read),
    villian(new Perms[] {});
    
    public Perms[] perms;
    RolesPerms(Perms... perms) {
      this.perms = perms;
    }
    
    public Perms[] getPerms(Roles role) {
      return valueOf(role.name()).perms;
    }
  }
  
  public enum UserPerms {
    batman(Perms.all()),
    robin(Perms.read,Perms.write,Perms.create),
    joker(Perms.all());
    
    public Perms[] perms;
    UserPerms(Perms... perms) {
      this.perms = perms;
    }
    
    public Perms[] getPerms(Roles role) {
      return valueOf(role.name()).perms;
    }
  }
}
