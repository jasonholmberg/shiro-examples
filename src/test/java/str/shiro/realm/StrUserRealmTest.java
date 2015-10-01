/**
 * 
 */
package str.shiro.realm;

import static org.junit.Assert.*;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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
import str.shiro.enums.Status;
import str.shiro.model.User;
import str.shiro.service.UserService;

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
    userService = spy(new MockUserService());
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
    
//    when(userService.authenticate(eq(username), eq(password))).thenReturn(new AuthInfo(true, new AuthMessage(AuthMessage.MSG_SUCCESS, null)));
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
    
//    when(userService.authenticate(eq(username), eq(password))).thenReturn(new AuthInfo(false, new AuthMessage(AuthMessage.MSG_FAIL, new Exception())));
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
  
  Subject shiroAuthcHelper(final String username, final String password) {
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
  
  class MockUserService implements UserService {
    
    
    @Override
    public User findUser(String username) {
      User user = new MockUser(Users.valueOf(username));
      if(SecurityUtils.getSubject().isPermitted("user:read:"+user.getId())) {
        return user;
      }
      return null;
    }

    @Override
    public List<User> findUsers() {
      List<User> users = new ArrayList<>();
      for (Users u : Users.values()) {
        if(SecurityUtils.getSubject().isPermitted("user:read:"+u.id)) {
          users.add(new MockUser(u));
        }
      }
      return users;
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
        for (String perm : RolesPerms.valueOf(role.name()).perms) {
          permissions.add(perm);
        }
      }
      
      for(String perm : UserPerms.valueOf(username).perms) {
        permissions.add(perm);
      }
      return permissions;
    }
    
  }
  
  class MockUser implements User {

    final int id;
    final String firstname;
    final String lastname;
    final String username;
    final byte[] password;
    final Status status;
    
    public MockUser(Users user) {
      this.id = user.id;
      this.firstname = user.name();
      this.lastname = user.lastname;
      this.username = user.name();
      this.password = user.password.getBytes();
      this.status = user.status;
    }
    
    @Override
    public int getId() {
      return id;
    }
    
    @Override
    public String getFirstname() {
      return firstname;
    }

    @Override
    public String getLastname() {
      return lastname;
    }

    @Override
    public String getUsername() {
      return username;
    }

    @Override
    public byte[] getPassword() {
      return password;
    }

    @Override
    public Status getStatus() {
      return status;
    }
    
    @Override
    public String toString() {
      return username;
    }
  }
  
  public enum Users {
    batman(1,"b4tg1rl","the Caped Crusader", "batman",Status.active),
    robin(2, "b4tg1rl","the Boy Wonder", "robin", Status.active),
    joker(3,"h@rl3y","the Villian", "jerome", Status.locked);
    
    public int id;
    public String password;
    public String lastname;
    public String username;
    public Status status;
    Users(int id, String password, String lastname, String username, Status status) {
      this.id = id;
      this.password = password;
      this.lastname = lastname;
      this.username = username;
      this.status = status;
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
    public static String[] all() {
      List<String> perms = new ArrayList<>(Perms.values().length);
      for(Perms perm : Perms.values()) {
        perms.add(perm.name());
      }
      return perms.toArray(new String[Perms.values().length]);
    }
  }
  
  public enum RolesPerms {
    admin(Perms.all()),
    hero(Perms.read.name(), Perms.write.name()),
    user(Perms.read.name()),
    villian(new String[] {});
    
    public String[] perms;
    RolesPerms(String... perms) {
      this.perms = perms;
    }
    
    public String[] getPerms(Roles role) {
      return valueOf(role.name()).perms;
    }
  }
  
  public enum UserPerms {
    batman(Perms.read.name(),Perms.write.name(),Perms.create.name(),Perms.delete.name(),"user:*"),
    robin(Perms.read.name(),Perms.write.name(),Perms.create.name(),"user:read:2,3"),
    joker(Perms.all());
    
    public String[] perms;
    UserPerms(String... perms) {
      this.perms = perms;
    }
    
    public String[] getPerms(Roles role) {
      return valueOf(role.name()).perms;
    }
  }
}
