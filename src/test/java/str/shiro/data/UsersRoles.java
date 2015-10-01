/**
 * 
 */
package str.shiro.data;

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
}