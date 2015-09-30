/**
 * 
 */
package str.shiro.realm;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Set;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.Realm;
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
    batman(Users.batman,new Roles[] {Roles.admin, Roles.user, Roles.hero}),
    robin(Users.robin,new Roles[] {Roles.user, Roles.hero}),
    joker(Users.joker,new Roles[] {Roles.villian, Roles.user});
    
    public Roles[] roles;
    public Users user;
    UsersRoles(Users user, Roles[] roles) {
      this.user = user;
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
  }
  
  public enum UserPerms {
    batman(Perms.all()),
    robin(Perms.read,Perms.write,Perms.create),
    joker(Perms.all());
    
    public Perms[] perms;
    UserPerms(Perms... perms) {
      this.perms = perms;
    }
    
  }
  
  @Mock
  private UserService userService;

  /**
   * @throws java.lang.Exception
   */
  @Before
  public void setUp() throws Exception {
    MockitoAnnotations.initMocks(this);
  }

  @Test
  public void authSuccess() {
    final String username = "batman";
    final String password = "b4tg1rl";
    AuthenticationToken token = mock(AuthenticationToken.class);
    when(token.getPrincipal()).thenReturn(username);
    when(token.getCredentials()).thenReturn(password);
    
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
    when(token.getCredentials()).thenReturn(password);
    
    when(userService.authenticate(eq(username), eq(password))).thenReturn(new AuthInfo(false, new AuthMessage(AuthMessage.MSG_FAIL, new Exception())));
    
    Realm realm = new StrUserRealm(userService);
    realm.getAuthenticationInfo(token);
    
    realm.getAuthenticationInfo(token);
  }
  
  @Test
  public void authzTest() {
    Realm realm = new StrUserRealm(userService);
    DefaultSecurityManager securityManager = new DefaultSecurityManager(realm);
    SecurityUtils.setSecurityManager(securityManager);
    
    
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
      // TODO Auto-generated method stub
      return null;
    }

    @Override
    public Set<String> getUserRoles(String username) {
      // TODO Auto-generated method stub
      return null;
    }

    @Override
    public Set<String> getPermissions(String username) {
      // TODO Auto-generated method stub
      return null;
    }
    
  }
  
}
