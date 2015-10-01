/**
 * 
 */
package str.shiro.data;

import str.shiro.enums.Status;

public enum Users {
  batman(1,"5/1/1939","b4tg1rl","the Caped Crusader", "batman",Status.active),
  robin(2, "4/1/1940", "b4tg1rl","the Boy Wonder", "robin", Status.active),
  joker(3, "4/25/1940", "h@rl3y","the Villian", "jerome", Status.locked);
  
  public int id;
  public String dob;
  public String password;
  public String lastname;
  public String username;
  public Status status;
  Users(int id, String dob, String password, String lastname, String username, Status status) {
    this.id = id;
    this.dob = dob;
    this.password = password;
    this.lastname = lastname;
    this.username = username;
    this.status = status;
  }
}