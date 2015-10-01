package str.shiro.service.impl;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import str.shiro.auth.AuthInfo;
import str.shiro.auth.AuthMessage;
import str.shiro.data.Roles;
import str.shiro.data.RolesPerms;
import str.shiro.data.UserPerms;
import str.shiro.data.Users;
import str.shiro.data.UsersRoles;
import str.shiro.model.MockUser;
import str.shiro.model.User;
import str.shiro.service.UserService;

public class MockUserService implements UserService {

  @Override
  public User findUser(String username) {
    User user = new MockUser(Users.valueOf(username));
    return user;
  }

  @Override
  public List<User> findUsers() {
    List<User> users = new ArrayList<>();
    for (Users u : Users.values()) {
      users.add(new MockUser(u));
    }
    return users;
  }

  @Override
  public AuthInfo authenticate(String username, String password) {
    Users user = Users.valueOf(username);
    if (user != null && user.password.equals(password)) {
      return new AuthInfo(true, new AuthMessage(AuthMessage.MSG_SUCCESS, null));
    } else {
      return new AuthInfo(false, new AuthMessage(AuthMessage.MSG_FAIL, new Exception("Authentication failed")));
    }
  }

  @Override
  public Set<String> getUserRoles(String username) {
    UsersRoles usersRoles = UsersRoles.valueOf(username);
    Set<String> roles = new HashSet<>();
    for (Roles role : usersRoles.roles) {
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

    for (String perm : UserPerms.valueOf(username).perms) {
      permissions.add(perm);
    }
    return permissions;
  }

}