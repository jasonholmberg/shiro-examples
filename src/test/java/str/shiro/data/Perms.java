/**
 * 
 */
package str.shiro.data;

import java.util.ArrayList;
import java.util.List;

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