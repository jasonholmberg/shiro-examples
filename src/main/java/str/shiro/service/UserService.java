/**
 * 
 */
package str.shiro.service;

import java.util.List;
import java.util.Set;

import str.shiro.auth.AuthInfo;
import str.shiro.model.User;

/**
 * @author Jason Holmberg
 *
 */
public interface UserService {
  User findUser(String username);
  List<User> findUsers();
  AuthInfo authenticate(String username, String password);
  Set<String> getUserRoles(String username);
  Set<String> getPermissions(String username);
}
