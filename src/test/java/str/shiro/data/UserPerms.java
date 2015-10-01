/**
 * 
 */
package str.shiro.data;

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