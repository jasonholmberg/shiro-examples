/**
 * 
 */
package str.shiro.service.impl;

import java.util.ArrayList;
import java.util.List;

import org.apache.shiro.SecurityUtils;

import str.shiro.data.Users;
import str.shiro.model.MockUser;
import str.shiro.model.User;

/**
 * @author Jason Holmberg
 *
 */
public class SecuredMockUserService extends MockUserService {

  @Override
  public User findUser(String username) {
    User user = new MockUser(Users.valueOf(username));
    if (SecurityUtils.getSubject().isPermitted("user:read:" + user.getId())) {
      return user;
    }
    return null;
  }

  @Override
  public List<User> findUsers() {
    List<User> users = new ArrayList<>();
    for (Users u : Users.values()) {
      if (SecurityUtils.getSubject().isPermitted("user:read:" + u.id)) {
        users.add(new MockUser(u));
      }
    }
    return users;
  }
}
