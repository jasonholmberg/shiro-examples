/**
 * 
 */
package str.shiro.data;

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